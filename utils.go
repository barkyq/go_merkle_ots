package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
)

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

func write_varint(w io.Writer, j int64) (int64, error) {
	if j < 0 {
		return 0, fmt.Errorf("must be non-negative")
	}
	for {
		if j > 127 {
			if _, e := w.Write([]byte{128 + byte(j%128)}); e != nil {
				return 0, e
			}
			j = j / 128
		} else {
			k, e := w.Write([]byte{byte(j)})
			return int64(k), e
		}
	}
}

func read_varint(r io.Reader) (j int64) {
	var b [1]byte
	builder := make([]byte, 0)
	for {
		if _, e := r.Read(b[:]); e != nil {
			panic(e)
		}
		if b[0] > 128 {
			builder = append(builder, b[0]-128)
		} else {
			builder = append(builder, b[0])
			break
		}
	}
	var power int64 = 1
	for _, v := range builder {
		j += int64(v) * power
		power *= 128
	}
	return
}
