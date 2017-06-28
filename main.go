package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"
)

// A web version of Marek's script

var (
	SSDP_SEARCH_P = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: %s\r\n\r\n"
	SERVER_RE     = regexp.MustCompile("(?i)server: ?([^\r\n]*)[\r\n]")
	ST_RE         = regexp.MustCompile("(?i)st: ?([^\r\n]*)[\r\n]")

	listenAddr     string
	httplistenAddr string
	protocol       string
	ssdpST         string
	conn           *net.UDPConn
	nrequestchan   chan notifyRequest
)

func init() {
	flag.StringVar(&listenAddr, "udplisten", "0.0.0.0:0", "Listen address")
	flag.StringVar(&httplistenAddr, "httplisten", "0.0.0.0:753", "Listen address")
	flag.StringVar(&protocol, "p", "udp", "udp/udp4/udp6")
	flag.StringVar(&ssdpST, "s", "ssdp:all", "ssdp ST")
}

func main() {
	flag.Parse()

	addr, err := net.ResolveUDPAddr(protocol, listenAddr)
	if err != nil {
		panic(err)
	}

	conn, err = net.ListenUDP(protocol, addr)
	if err != nil {
		panic(err)
	}

	fs := http.FileServer(http.Dir("public"))
	http.Handle("/", fs)

	http.HandleFunc("/test", testClient)

	nrequestchan = make(chan notifyRequest)
	go resultCollector(nrequestchan)

	fmt.Printf("Failed to start, %s", http.ListenAndServe(httplistenAddr, nil).Error())
}

type notifyRequest struct {
	ip string
	c  chan bool
}

func testClient(w http.ResponseWriter, rw *http.Request) {
	SSDP_SEARCH := []byte(fmt.Sprintf(SSDP_SEARCH_P, ssdpST))

	addr, err := net.ResolveUDPAddr(protocol, fmt.Sprintf("%s:1900", rw.Header.Get("CF-Connecting-IP")))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ ] Can't resolve %s\n", rw.Header.Get("CF-Connecting-IP"))
		http.Error(w, "Unable to resolve IP", http.StatusInternalServerError)
		return
	}

	notifyChan := make(chan bool)
	request := notifyRequest{
		ip: rw.Header.Get("CF-Connecting-IP"),
		c:  notifyChan,
	}

	_, err = conn.WriteToUDP(SSDP_SEARCH, addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ ] write(%s) failed: %s\n", rw.Header.Get("CF-Connecting-IP"), err)
		http.Error(w, "Unable to produce packet", http.StatusInternalServerError)
		return
	}
	nrequestchan <- request

	select {
	case <-notifyChan:
		w.Write([]byte(`{"result":true}`))
	case <-time.After(time.Second * 5):
		w.Write([]byte(`{"result":false}`))
	}

	close(notifyChan)
}

func resultCollector(notifyrequests chan notifyRequest) {

	waiting := make(map[string]notifyRequest)
	requestlock := sync.Mutex{}

	go func() {
		for r := range notifyrequests {
			requestlock.Lock()

			waiting[r.ip] = r

			requestlock.Unlock()
		}
	}()

	for {
		var buf [2048]byte
		n, remote, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ ] read(): %s\n", err)
			continue
		}
		data := buf[:n]
		m := SERVER_RE.FindAllSubmatch(data, -1)
		server := []byte{}
		if len(m) > 0 && len(m[0]) > 1 {
			server = m[0][1]
		}

		m = ST_RE.FindAllSubmatch(data, -1)
		st := []byte{}
		if len(m) > 0 && len(m[0]) > 1 {
			st = m[0][1]
		}

		sport := 0
		if remote.Port == 1900 {
			sport = 1
		}
		fmt.Printf("%s\t%d\t%d\t%s\t%s\n", remote.IP, n, sport, st, server)

		select {
		case waiting[remote.IP.String()].c <- true:
		default:
		}

		delete(waiting, remote.IP.String())

	}
}
