package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"

	"strconv"
	"strings"
)

const blockstream = "blockstream.info"

func MerkleRoot(height int64) ([]byte, error) {
	var conn io.ReadWriter
	if c, e := tls.Dial("tcp", blockstream+":443", &tls.Config{ServerName: blockstream}); e != nil {
		return nil, e
	} else {
		conn = c
	}
	wb := bufio.NewWriter(conn)
	wb.Write([]byte(fmt.Sprintf("GET /api/block-height/%d HTTP/1.1\r\n", height)))
	wb.Write([]byte(fmt.Sprintf("Host: %s\r\n", blockstream)))
	wb.Write([]byte("User-Agent: barkyq-http-client/1.0\r\n"))
	wb.Write([]byte("Accept: plain/text\r\n"))
	wb.Write([]byte("\r\n"))
	wb.Flush()

	rb := bufio.NewReader(conn)
	var hex_hash [64]byte
	if r, err := read_chunked(rb); err != nil {
		return nil, err
	} else {
		r.Read(hex_hash[:])
	}
	wb.Write([]byte(fmt.Sprintf("GET /api/block/%s HTTP/1.1\r\n", hex_hash)))
	wb.Write([]byte(fmt.Sprintf("Host: %s\r\n", blockstream)))
	wb.Write([]byte("User-Agent: barkyq-http-client/1.0\r\n"))
	wb.Write([]byte("Accept: application/json\r\n"))
	wb.Write([]byte("\r\n"))
	wb.Flush()
	if r, err := read_chunked(rb); err != nil {
		return nil, err
	} else {
		dec := json.NewDecoder(r)
		m := make(map[string]any)
		dec.Decode(&m)
		if merkle_root, ok := m["merkle_root"].(string); ok != true {
			return nil, fmt.Errorf("invalid merkle root")
		} else {
			return hex.DecodeString(merkle_root)
		}
	}
}

// SubmitDigest takes URI of form https://calendar.com/ and a digest to be posted.
// Returns a reader containing the response
func SubmitDigest(URI *url.URL, digest []byte) (r io.Reader, err error) {
	var conn io.ReadWriter
	if c, e := tls.Dial("tcp", URI.Host+fmt.Sprintf(":%d", *port), &tls.Config{ServerName: URI.Hostname()}); e != nil {
		err = e
		return
	} else {
		conn = c
	}
	wb := bufio.NewWriter(conn)
	wb.Write([]byte(fmt.Sprint("POST /digest HTTP/1.1\r\n")))
	wb.Write([]byte(fmt.Sprintf("Host: %s\r\n", URI.Hostname())))
	wb.Write([]byte("User-Agent: barkyq-http-client/1.0\r\n"))
	wb.Write([]byte("Accept: application/vnd.opentimestamps.v1\r\n"))
	wb.Write([]byte("Content-Type: application/x-www-form-urlencoded\r\n"))
	wb.Write([]byte("Content-Length: 32\r\n"))
	wb.Write([]byte("\r\n"))
	wb.Write(digest)
	wb.Flush()

	rb := bufio.NewReader(conn)
	return read_chunked(rb)
}

// GetTimestamp takes a URI of form "https://calendar.com/timestamp/TIMESTAMP_HEX".
// Returns r containing the response (a Proof fragment, missing the header).
func GetTimestamp(URI *url.URL) (r io.Reader, err error) {
	var conn io.ReadWriter
	if c, e := tls.Dial("tcp", URI.Host+fmt.Sprintf(":%d", *port), &tls.Config{ServerName: URI.Hostname()}); e != nil {
		err = e
		return
	} else {
		conn = c
	}
	wb := bufio.NewWriter(conn)
	wb.Write([]byte(fmt.Sprintf("GET %s HTTP/1.1\r\n", URI.Path)))
	wb.Write([]byte(fmt.Sprintf("Host: %s\r\n", URI.Hostname())))
	wb.Write([]byte("User-Agent: barkyq-http-client/1.0\r\n"))
	wb.Write([]byte("Accept: application/vnd.opentimestamps.v1\r\n"))
	wb.Write([]byte("Content-Type: application/x-www-form-urlencoded\r\n"))
	wb.Write([]byte("\r\n"))
	wb.Flush()

	rb := bufio.NewReader(conn)
	return read_chunked(rb)
}

// helper for reading chunked data
func read_chunked(rb *bufio.Reader) (r io.Reader, err error) {
	var chunked bool
	var content_encoding string
	for {
		header_line, err := rb.ReadString('\n')
		if err != nil {
			panic(err)
		}
		if arr := strings.Split(header_line, ":"); len(arr) > 1 {
			key := strings.TrimSpace(strings.ToLower(arr[0]))
			val := strings.TrimSpace(strings.ToLower(arr[1]))
			switch key {
			case "transfer-encoding":
				if val == "chunked" {
					chunked = true
				}
			case "content-encoding":
				content_encoding = val
			default:
			}
		}
		if header_line == "\r\n" {
			// break at the empty CRLF
			break
		}
	}
	_, _ = chunked, content_encoding

	if chunked {
		var tmp [32]byte
		data_buf := bytes.NewBuffer(nil)
		for {
			chunk, e := rb.ReadString('\n')
			if e != nil {
				err = e
				return
			}
			chunk_size, e := strconv.ParseInt(strings.TrimSpace(chunk), 16, 64)
			if e != nil {
				err = e
				return
			}
			if chunk_size == 0 {
				rb.Discard(2)
				// finished chunking
				break
			}
			for chunk_size > 32 {
				if n, e := rb.Read(tmp[:]); e == nil {
					chunk_size -= int64(n)
					data_buf.Write(tmp[:n])
				} else {
					err = e
					return
				}
			}
			if n, err := rb.Read(tmp[:chunk_size]); err == nil {
				data_buf.Write(tmp[:n])
			}
			// chunk size does not account for CRLF added to end of chunk data
			rb.Discard(2)
		}
		return data_buf, nil
	} else {
		return rb, nil
	}
}
