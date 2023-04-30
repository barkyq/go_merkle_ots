package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"time"

	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const MAJOR_VERSION = 0x01

var BTC_attestation = [8]byte{0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01}
var Pending_attestation = [8]byte{0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e}
var HEADER_MAGIC = [31]byte{0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94}

type MerkleTree interface {
	Digest() []byte
	Proof(footer []Op, proofs chan Proof) error
}

type Proof struct {
	Leaf  *Leaf
	Proof []Op
}

type Op struct {
	Tag byte
	Arg []byte
}

type Fork struct {
	digest []byte
	Left   MerkleTree
	Right  MerkleTree
}

func (f *Fork) Proof(footer []Op, proofs chan Proof) error {
	il := []Op{{0xf0, f.Right.Digest()}, {0x08, f.Digest()}}
	ir := []Op{{0xf1, f.Left.Digest()}, {0x08, f.Digest()}}
	il = append(il, footer...)
	ir = append(ir, footer...)
	if e := f.Left.Proof(il, proofs); e != nil {
		return e
	}
	if e := f.Right.Proof(ir, proofs); e != nil {
		return e
	}
	return nil
}

func (f *Fork) Digest() []byte {
	if len(f.digest) == 32 {
		return f.digest
	}
	h := sha256.New()
	h.Write(f.Left.Digest())
	h.Write(f.Right.Digest())
	f.digest = h.Sum(nil)
	return f.digest
}

type Leaf struct {
	name   string
	digest [32]byte
}

func (v *Leaf) Proof(footer []Op, proofs chan Proof) error {
	proofs <- Proof{v, footer}
	return nil
}

func (v *Leaf) Digest() []byte {
	return v.digest[:]
}

var upgrade = flag.String("u", "", "upgrade pending .ots file")
var directory = flag.String("d", "", "directory of files to stamp")
var calendar = flag.String("c", "https://finney.calendar.eternitywall.com", "calendar")
var port = flag.Int("port", 443, "port")

func main() {
	flag.Parse()
	output_dir_name := "proofs_" + time.Now().Format("2006_01_02")
	if _, e := os.Stat(*directory); e != nil {
		panic("set the -d option")
	}
	var leaf []byte
	var footer []byte
	if *upgrade != "" {
		if f, err := os.Open(*upgrade); err != nil {
			panic(err)
		} else {
			buf := bytes.NewBuffer(nil)
			if l, err := parse_header(f); err != nil {
				panic(err)
			} else {
				leaf = l
				if err = upgrade_timestamp(f, l, buf); err != nil {
					fmt.Println(err.Error())
					os.Exit(0)
				}
				footer = buf.Bytes()
			}
		}
	}

	builder := make([]MerkleTree, 0)
	h := sha256.New()
	file_tree := os.DirFS(*directory)
	buffer := make([]byte, 1024)
	number_of_files := 0
	if e := fs.WalkDir(file_tree, ".", func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}
		number_of_files++
		v := Leaf{name: d.Name()}
		if f, e := file_tree.Open(path); e == nil {
			io.CopyBuffer(h, f, buffer)
			f.Close()
		} else {
			return e
		}
		copy(v.digest[:], h.Sum(nil))
		h.Reset()
		builder = append(builder, &v)
		return nil
	}); e != nil {
		panic(e)
	}

	// sort the inputs by digest
	// to have deterministic merkle tree
	sort.Slice(builder, func(i, j int) bool {
		dg1 := builder[i].Digest()
		dg2 := builder[j].Digest()
		for k, v := range dg1 {
			if dg2[k] > v {
				return true
			}
			if dg2[k] < v {
				return false
			}
		}
		return false
	})

	// build merkle tree
	for {
		if len(builder) == 1 {
			break
		} else {
			l := builder[0]
			r := builder[1]
			f := &Fork{
				Left:  l,
				Right: r,
			}
			builder = builder[2:]
			builder = append(builder, f)
		}

	}

	root := builder[0]
	root_digest := root.Digest()

	if *upgrade != "" {
		for k, v := range leaf {
			if root_digest[k] != v {
				panic("root digest does not match leaf digest")
			}
		}
	} else {
		if URI, err := url.Parse(*calendar); err != nil {
			panic(err)
		} else {
			if r, err := submit_digest(URI, root_digest); err != nil {
				panic(err)
			} else {
				filename := "pending_" + time.Now().Format("2006_01_02") + ".ots"
				if w, e := os.Create(filename); e == nil {
					w.Write(HEADER_MAGIC[:])
					w.Write([]byte{MAJOR_VERSION, 0x08})
					w.Write(root_digest)
					io.Copy(w, r)
					w.Close()
				} else {
					panic(e)
				}
			}
		}
		return
	}

	proofs := make(chan Proof, 64)
	go root.Proof([]Op{}, proofs)

	if e := os.MkdirAll(output_dir_name, os.ModePerm); e != nil {
		panic(e)
	}

	for i := 0; i < number_of_files; i++ {
		select {
		case p := <-proofs:
			if f, e := os.Create(filepath.Join(output_dir_name, p.Leaf.name+".ots")); e != nil {
				panic(e)
			} else {
				if n, e := p.WriteTo(f); e != nil {
					panic(e)
				} else {
					if k, e := f.Write(footer); e != nil {
						panic(e)
					} else {
						fmt.Println(p.Leaf.name, n+int64(k))
					}
				}
				f.Close()
			}
		}
	}
}

func (p *Proof) WriteTo(f io.Writer) (n int64, err error) {
	if k, e := f.Write(HEADER_MAGIC[:]); e != nil {
		err = e
		return
	} else {
		n += int64(k)
	}
	if k, e := f.Write([]byte{MAJOR_VERSION, 0x08}); e != nil {
		err = e
		return
	} else {
		n += int64(k)
	}
	if k, e := f.Write(p.Leaf.digest[:]); e != nil {
		err = e
		return
	} else {
		n += int64(hex.EncodedLen(k))
	}
	for _, i := range p.Proof {
		if k, e := f.Write([]byte{i.Tag}); e != nil {
			err = e
			return
		} else {
			n += int64(k)
		}
		switch {
		case i.Tag == 0xf1 || i.Tag == 0xf0:
			if k, e := write_varint(f, int64(len(i.Arg))); e != nil {
				err = e
				return
			} else {
				n += int64(k)
			}
			if k, e := f.Write(i.Arg); e != nil {
				err = e
				return
			} else {
				n += int64(k)
			}
		}
	}
	return
}

func parse_header(r io.Reader) ([]byte, error) {
	var magic [31]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, err
	} else {
		if magic != HEADER_MAGIC {
			return nil, fmt.Errorf("Invalid Header Magic!")
		}
	}
	r.Read(magic[:1])
	if magic[0] != MAJOR_VERSION {
		return nil, fmt.Errorf("Incompatible Major Version!")
	}
	r.Read(magic[:1])
	hash_type := magic[0]
	var hash_length int64
	switch hash_type {
	case 0x08:
		hash_length = 32
	default:
		return nil, fmt.Errorf("Unknown Hash Type!")
	}
	leaf := make([]byte, hash_length)
	_, err := io.ReadFull(r, leaf)
	return leaf, err
}

func upgrade_timestamp(r io.Reader, leaf []byte, buf *bytes.Buffer) (err error) {
	result := make([]byte, 0)
	result = append(result, leaf...)
	var attestation [8]byte
	var tag [1]byte
	sha256 := sha256.New()

	for {
		if _, err = r.Read(tag[:]); err != nil {
			return
		}
		switch {
		case tag[0] == 0x08:
			buf.Write(tag[:])
			sha256.Reset()
			if _, err = sha256.Write(result); err != nil {
				return
			}
			result = sha256.Sum(nil)
		case tag[0] == 0xf1 || tag[0] == 0xf0:
			buf.Write(tag[:])
			j := read_varint(r)
			write_varint(buf, j)
			piece := make([]byte, j)
			if _, err = io.ReadFull(r, piece); err != nil {
				return
			}
			buf.Write(piece)
			switch tag[0] {
			case 0xf1:
				result = append(piece, result...)
			case 0xf0:
				result = append(result, piece...)
			}
		case tag[0] == 0x00:
			if _, err = io.ReadFull(r, attestation[:]); err != nil {
				return
			}
			return upgrade_attestation(r, attestation, result, buf)
		case tag[0] == 0xff:
			if err = upgrade_timestamp(r, result, buf); err != nil {
				return
			}
		default:
			err = fmt.Errorf("unknown tag")
			return
		}
	}
}

func upgrade_attestation(r io.Reader, attestation [8]byte, result []byte, buf *bytes.Buffer) error {
	switch attestation {
	case BTC_attestation:
		buf.Write([]byte{0x00})
		buf.Write(attestation[:])
		j := read_varint(r)
		write_varint(buf, j)
		j = read_varint(r)
		write_varint(buf, j)
		return nil
	case Pending_attestation:
		// buf.Write([]byte{0xff, 0x00})
		// buf.Write(attestation[:])
		j := read_varint(r)
		// write_varint(buf, j)
		raw_uri := make([]byte, j)
		io.ReadFull(r, raw_uri)
		// buf.Write(raw_uri)
		if URI, err := url.Parse(fmt.Sprintf("%s/timestamp/%x", raw_uri[1:], result)); err != nil {
			return err
		} else {
			if ur, err := get_timestamp(URI); err != nil {
				return err
			} else {
				var tester [1]byte
				ur.Read(tester[:])
				if tester[0] != 0x08 && tester[0] != 0xf0 && tester[0] != 0xf1 {
					return fmt.Errorf("Pending Confirmation in Blockchain")
				} else {
					buf.Write(tester[:])
					_, err = io.Copy(buf, ur)
					return err
				}
			}
		}
	default:
		return fmt.Errorf("unknown attestation")
	}

}

func submit_digest(URI *url.URL, digest []byte) (r io.Reader, err error) {
	var conn io.ReadWriter
	if c, e := tls.Dial("tcp", URI.Host+fmt.Sprintf(":%d", port), &tls.Config{ServerName: URI.Hostname()}); e != nil {
		err = e
		return
	} else {
		conn = c
	}
	wb := bufio.NewWriter(conn)
	wb.Write([]byte(fmt.Sprint("POST /digest HTTP/1.1\r\n", URI.Path)))
	wb.Write([]byte(fmt.Sprintf("Host: %s\r\n", URI.Hostname())))
	wb.Write([]byte("User-Agent: barkyq-http-client/1.0\r\n"))
	wb.Write([]byte("Accept: application/vnd.opentimestamps.v1\r\n"))
	wb.Write([]byte("Content-Type: application/x-www-form-urlencoded\r\n"))
	wb.Write([]byte("Content-Length: 32\r\n"))
	wb.Write([]byte("\r\n"))
	wb.Flush()
	wb.Write(digest)
	wb.Flush()
	rb := bufio.NewReader(conn)
	return read_chunked(rb)
}

func get_timestamp(URI *url.URL) (r io.Reader, err error) {
	var conn io.ReadWriter

	if c, e := tls.Dial("tcp", URI.Host+fmt.Sprintf(":%d", *port), &tls.Config{ServerName: URI.Hostname()}); e != nil {
		err = e
		return
	} else {
		conn = c
	}
	wb := bufio.NewWriter(conn)
	wb.Write([]byte(fmt.Sprintf("GET /%s HTTP/1.1\r\n", URI.Path)))
	wb.Write([]byte(fmt.Sprintf("Host: %s\r\n", URI.Hostname())))
	wb.Write([]byte("User-Agent: barkyq-http-client/1.0\r\n"))
	wb.Write([]byte("Accept: application/vnd.opentimestamps.v1\r\n"))
	wb.Write([]byte("Content-Type: application/x-www-form-urlencoded\r\n"))
	wb.Write([]byte("\r\n"))
	wb.Flush()

	rb := bufio.NewReader(conn)
	return read_chunked(rb)
}

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

func (p *Proof) PrettyWriteTo(f io.Writer) (n int64, err error) {
	w := hex.NewEncoder(f)
	if k, e := f.Write([]byte("# leaf ")); e != nil {
		err = e
		return
	} else {
		n += int64(k)
	}
	if k, e := w.Write(p.Leaf.digest[:]); e != nil {
		err = e
		return
	} else {
		n += int64(hex.EncodedLen(k))
	}
	if k, e := f.Write([]byte{'\r', '\n'}); e != nil {
		err = e
		return
	} else {
		n += int64(k)
	}
	for _, i := range p.Proof {
		switch i.Tag {
		case 0xf1:
			if k, e := f.Write([]byte("prepend ")); e != nil {
				err = e
				return
			} else {
				n += int64(k)
			}
			if k, e := w.Write(i.Arg); e != nil {
				err = e
				return
			} else {
				n += int64(hex.EncodedLen(k))
			}
			if k, e := f.Write([]byte{'\r', '\n'}); e != nil {
				err = e
				return
			} else {
				n += int64(k)
			}
		case 0xf0:
			if k, e := f.Write([]byte("append ")); e != nil {
				err = e
				return
			} else {
				n += int64(k)
			}
			if k, e := w.Write(i.Arg); e != nil {
				err = e
				return
			} else {
				n += int64(hex.EncodedLen(k))
			}
			if k, e := f.Write([]byte{'\r', '\n'}); e != nil {
				err = e
				return
			} else {
				n += int64(k)
			}
		case 0x08:
			if k, e := f.Write([]byte{'s', 'h', 'a', '2', '5', '6', '\r', '\n'}); e != nil {
				err = e
				return
			} else {
				n += int64(k)
			}
		case 0x00:
			if k, e := f.Write([]byte("verify ")); e != nil {
				err = e
				return
			} else {
				n += int64(k)
			}
			if k, e := w.Write(i.Arg); e != nil {
				err = e
				return
			} else {
				n += int64(hex.EncodedLen(k))
			}
			if k, e := f.Write([]byte{'\r', '\n'}); e != nil {
				err = e
				return
			} else {
				n += int64(k)
			}
		}
	}
	return
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
