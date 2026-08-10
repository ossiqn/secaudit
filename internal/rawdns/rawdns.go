package rawdns

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

const defaultDNS = "8.8.8.8:53"

func buildQuery(domain string, qtype uint16, edns bool) []byte {
	buf := make([]byte, 512)
	id := uint16(rand.Intn(65535))
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], 0x0100)
	binary.BigEndian.PutUint16(buf[4:6], 1)
	binary.BigEndian.PutUint16(buf[6:8], 0)
	binary.BigEndian.PutUint16(buf[8:10], 0)
	if edns {
		binary.BigEndian.PutUint16(buf[10:12], 1)
	} else {
		binary.BigEndian.PutUint16(buf[10:12], 0)
	}

	offset := 12
	parts := strings.Split(domain, ".")
	for _, p := range parts {
		buf[offset] = byte(len(p))
		offset++
		copy(buf[offset:], []byte(p))
		offset += len(p)
	}
	buf[offset] = 0
	offset++

	binary.BigEndian.PutUint16(buf[offset:offset+2], qtype)
	offset += 2
	binary.BigEndian.PutUint16(buf[offset:offset+2], 1)
	offset += 2

	if edns {
		buf[offset] = 0
		offset++
		binary.BigEndian.PutUint16(buf[offset:offset+2], 41)
		offset += 2
		binary.BigEndian.PutUint16(buf[offset:offset+2], 4096)
		offset += 2
		binary.BigEndian.PutUint32(buf[offset:offset+4], 0)
		offset += 4
		binary.BigEndian.PutUint16(buf[offset:offset+2], 0)
		offset += 2
	}

	return buf[:offset]
}

func sendUDP(query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", defaultDNS, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(query)
	if err != nil {
		return nil, err
	}
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		return nil, err
	}
	return resp[:n], nil
}

func sendTCP(query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", defaultDNS, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(query)))
	_, err = conn.Write(append(lenBuf, query...))
	if err != nil {
		return nil, err
	}

	_, err = conn.Read(lenBuf)
	if err != nil {
		return nil, err
	}
	respLen := binary.BigEndian.Uint16(lenBuf)
	resp := make([]byte, respLen)
	total := 0
	for total < int(respLen) {
		n, err := conn.Read(resp[total:])
		if err != nil {
			return nil, err
		}
		total += n
	}
	return resp, nil
}

func skipName(data []byte, offset int) int {
	for offset < len(data) {
		if data[offset]&0xC0 == 0xC0 {
			return offset + 2
		}
		if data[offset] == 0 {
			return offset + 1
		}
		offset += int(data[offset]) + 1
	}
	return offset
}

func readName(data []byte, offset int) (string, int) {
	var parts []string
	jumped := false
	retOffset := offset
	for offset < len(data) {
		if data[offset]&0xC0 == 0xC0 {
			if !jumped {
				retOffset = offset + 2
			}
			pointer := int(binary.BigEndian.Uint16(data[offset:offset+2])) & 0x3FFF
			offset = pointer
			jumped = true
			continue
		}
		if data[offset] == 0 {
			if !jumped {
				retOffset = offset + 1
			}
			break
		}
		length := int(data[offset])
		offset++
		if offset+length > len(data) {
			break
		}
		parts = append(parts, string(data[offset:offset+length]))
		offset += length
	}
	return strings.Join(parts, "."), retOffset
}

func query(domain string, qtype uint16) ([]byte, error) {
	q := buildQuery(domain, qtype, true)
	resp, err := sendUDP(q)
	if err != nil {
		return nil, err
	}
	if len(resp) >= 4 && resp[2]&0x02 != 0 {
		q2 := buildQuery(domain, qtype, false)
		resp2, err2 := sendTCP(q2)
		if err2 != nil {
			return resp, nil
		}
		return resp2, nil
	}
	return resp, nil
}

func parseAnswers(data []byte) (int, int) {
	if len(data) < 12 {
		return 0, 12
	}
	ancount := int(binary.BigEndian.Uint16(data[6:8]))
	offset := 12
	qdcount := int(binary.BigEndian.Uint16(data[4:6]))
	for i := 0; i < qdcount; i++ {
		offset = skipName(data, offset)
		offset += 4
	}
	return ancount, offset
}

type CAARecord struct {
	Flag  uint8
	Tag   string
	Value string
}

func LookupCAA(domain string) ([]CAARecord, error) {
	resp, err := query(domain, 257)
	if err != nil {
		return nil, err
	}
	ancount, offset := parseAnswers(resp)
	var records []CAARecord
	for i := 0; i < ancount && offset < len(resp); i++ {
		offset = skipName(resp, offset)
		if offset+10 > len(resp) {
			break
		}
		rtype := binary.BigEndian.Uint16(resp[offset : offset+2])
		rdlength := binary.BigEndian.Uint16(resp[offset+8 : offset+10])
		offset += 10
		if rtype == 257 && int(offset)+int(rdlength) <= len(resp) {
			rdata := resp[offset : offset+int(rdlength)]
			if len(rdata) >= 2 {
				flag := rdata[0]
				tagLen := int(rdata[1])
				if 2+tagLen <= len(rdata) {
					tag := string(rdata[2 : 2+tagLen])
					value := string(rdata[2+tagLen:])
					records = append(records, CAARecord{Flag: flag, Tag: tag, Value: value})
				}
			}
		}
		offset += int(rdlength)
	}
	return records, nil
}

func LookupDNSKEY(domain string) (bool, error) {
	resp, err := query(domain, 48)
	if err != nil {
		return false, err
	}
	ancount, _ := parseAnswers(resp)
	return ancount > 0, nil
}

func LookupDS(domain string) (bool, error) {
	resp, err := query(domain, 43)
	if err != nil {
		return false, err
	}
	ancount, _ := parseAnswers(resp)
	return ancount > 0, nil
}

func LookupTXT(domain string) ([]string, error) {
	resp, err := query(domain, 16)
	if err != nil {
		return nil, err
	}
	ancount, offset := parseAnswers(resp)
	var results []string
	for i := 0; i < ancount && offset < len(resp); i++ {
		offset = skipName(resp, offset)
		if offset+10 > len(resp) {
			break
		}
		rtype := binary.BigEndian.Uint16(resp[offset : offset+2])
		rdlength := binary.BigEndian.Uint16(resp[offset+8 : offset+10])
		offset += 10
		if rtype == 16 && int(offset)+int(rdlength) <= len(resp) {
			rdata := resp[offset : offset+int(rdlength)]
			pos := 0
			var txt string
			for pos < len(rdata) {
				slen := int(rdata[pos])
				pos++
				if pos+slen > len(rdata) {
					break
				}
				txt += string(rdata[pos : pos+slen])
				pos += slen
			}
			if txt != "" {
				results = append(results, txt)
			}
		}
		offset += int(rdlength)
	}
	return results, nil
}

func init() {
	rand.Seed(time.Now().UnixNano())
	_ = fmt.Sprintf("")
}
