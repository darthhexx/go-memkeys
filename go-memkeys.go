package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/jroimartin/gocui"
)

const (
	NumGoroutines = 4
	ColumnWidth   = 12
	SNAP_LENGTH   = 65536

	SortReq = iota
	SortReqPerSec
	SortResp
	SortRespPerSec
	SortSize
	SortBandwidth

	SortTypeDescending = iota
	SortTypeAscending
)

type CachedItem struct {
	Size               float32 `json:"size"`
	RequestCount       float32 `json:"reqCount"`
	RequestsPerSecond  float32 `json:"reqPerSec"`
	ResponseCount      float32 `json:"resCount"`
	ResponsesPerSecond float32 `json:"resPerSec"`
}

type SortObject struct {
	Key   string
	Value float32
}

type CachedResponsesSorted []SortObject

func (mr CachedResponsesSorted) Len() int           { return len(mr) }
func (mr CachedResponsesSorted) Less(i, j int) bool { return mr[i].Value < mr[j].Value }
func (mr CachedResponsesSorted) Swap(i, j int)      { mr[i], mr[j] = mr[j], mr[i] }

var (
	done           = make(chan struct{})
	columnSortBy   int
	columnSortType int

	mCachedItems        map[string]*CachedItem
	mCachedItemsPadlock *sync.Mutex

	payloadResponse *regexp.Regexp
	payloadRequest  *regexp.Regexp

	statsTimer       float32
	statsSecond      bool
	statsWriteToFile bool

	myIP4v, myIPv6 string

	nic  = flag.String("i", "en0", "Interface to read packets from")
	port = flag.Int("p", 11211, "Port number")
)

func main() {
	var handle *pcap.Handle
	var err error

	columnSortBy = SortBandwidth
	columnSortType = SortTypeDescending
	mCachedItemsPadlock = &sync.Mutex{}
	mCachedItems = make(map[string]*CachedItem)
	statsWriteToFile = false

	payloadResponse = regexp.MustCompile("^VALUE (\\S+) \\d+ (\\d+)")
	if nil == payloadResponse {
		log.Fatalf("Unable to compile the packet memcached response regex")
	}

	payloadRequest = regexp.MustCompile("^get (\\S+)\\r?\\n$")
	if nil == payloadRequest {
		log.Fatalf("Unable to compile the packet memcached get regex")
	}

	flag.Parse()

	if nil == port || 1024 > *port || 65536 < *port {
		log.Fatalf("Please speicify a listen ort between 1024 and 65536")
	}

	f, err := os.Create("cpu-profile")
	if err != nil {
		log.Fatalln("could not open cpu profile file")
	}

	pprof.StartCPUProfile(f)

	/*
		myIP4v, myIPv6, err = getInterfaceAddresses(*nic)
		if nil != err {
			log.Fatalf("Unable to determine interace %s's addresses: %s\n", *nic, err.Error())
		}
	*/

	bpffilter := fmt.Sprintf("port %d", *port)

	inactive, err := pcap.NewInactiveHandle(*nic)
	if err != nil {
		log.Fatalf("could not create: %v", err)
	}
	defer inactive.CleanUp()

	if err = inactive.SetSnapLen(SNAP_LENGTH); err != nil {
		log.Fatalf("could not set snap length: %v", err)
	} else if err = inactive.SetPromisc(true); err != nil {
		log.Fatalf("could not set promisc mode: %v", err)
	} else if err = inactive.SetTimeout(time.Second); err != nil {
		log.Fatalf("could not set timeout: %v", err)
	}

	if handle, err = inactive.Activate(); err != nil {
		log.Fatal("PCAP Activate error: ", err)
	}
	defer handle.Close()

	if len(flag.Args()) > 0 {
		bpffilter += " and ( " + strings.Join(flag.Args(), " ") + " )"
	}

	fmt.Fprintf(os.Stderr, "Using BPF filter %q\n", bpffilter)
	if err = handle.SetBPFFilter(bpffilter); err != nil {
		log.Fatal("BPF filter error:", err)
	}

	g, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		log.Panicln(err)
	}
	defer g.Close()

	g.Mouse = false
	g.Cursor = false
	g.SetManagerFunc(layout)

	setUpKeyEvents(g)

	for i := 0; i < NumGoroutines; i++ {
		go Run(handle)
	}

	paintHeader(g)
	paintData(g)
	paintStatus(g)

	go func() {
		halfSecChan := time.Tick(time.Duration(500 * time.Millisecond.Nanoseconds()))
		for {
			select {
			case <-done:
				g.Update(func(g *gocui.Gui) error {
					v, err := g.View("keys")
					if err != nil {
						return err
					}
					v.Clear()
					fmt.Fprintf(v, "all done!")
					return nil
				})
				return
			case <-halfSecChan:
				g.Update(func(g *gocui.Gui) error {
					err = paintHeader(g)
					if err != nil {
						return err
					}
					err = paintData(g)
					if err != nil {
						return err
					}
					err = paintStatus(g)
					if err != nil {
						return err
					}
					return nil
				})
			}
		}
	}()

	if err := g.MainLoop(); err != nil && err != gocui.ErrQuit {
		log.Panicln(err)
	}
}

func paintData(g *gocui.Gui) error {
	var k, req, reqps, res, resps, s, bw *gocui.View
	var err error

	k, err = g.View("keys")
	if err != nil {
		return err
	}
	req, err = g.View("req")
	if err != nil {
		return err
	}
	reqps, err = g.View("reqps")
	if err != nil {
		return err
	}
	res, err = g.View("res")
	if err != nil {
		return err
	}
	resps, err = g.View("resps")
	if err != nil {
		return err
	}
	s, err = g.View("size")
	if err != nil {
		return err
	}
	bw, err = g.View("bw")
	if err != nil {
		return err
	}

	k.Clear()
	req.Clear()
	reqps.Clear()
	res.Clear()
	resps.Clear()
	s.Clear()
	bw.Clear()

	sortedData := sortByColumn()
	_, maxY := g.Size()
	rowCount := 5 // 1 for the header + it's line separator and 2 for status bar and it's line separator

	for _, v := range sortedData {
		fmt.Fprintln(k, v.Key)
		mCachedItemsPadlock.Lock()
		item, found := mCachedItems[v.Key]
		mCachedItemsPadlock.Unlock()
		if found {
			fmt.Fprintf(req, "  %9.0f\n", item.RequestCount)
			fmt.Fprintf(reqps, "  %9.2f\n", item.RequestsPerSecond)
			fmt.Fprintf(res, "  %9.0f\n", item.ResponseCount)
			fmt.Fprintf(resps, "  %9.2f\n", item.ResponsesPerSecond)

			if -1 == item.Size {
				fmt.Fprintln(s, "      -")
			} else {
				fmt.Fprintf(s, "  %9.0f\n", item.Size)
			}
			if -1 == item.Size {
				fmt.Fprintln(bw, "      -")
			} else {
				fmt.Fprintf(bw, "  %9.2f\n", item.Size*item.ResponsesPerSecond/1024)
			}
		} else {
			fmt.Fprintln(req, "      -")
			fmt.Fprintln(reqps, "      -")
			fmt.Fprintln(res, "      -")
			fmt.Fprintln(resps, "      -")
			fmt.Fprintln(s, "      -")
			fmt.Fprintln(bw, "      -")
		}

		rowCount++
		if rowCount >= maxY {
			break
		}
	}

	statsSecond = !statsSecond
	if statsSecond {
		statsTimer++
		mCachedItemsPadlock.Lock()
		for _, v := range mCachedItems {
			v.RequestsPerSecond = v.RequestCount / statsTimer
			v.ResponsesPerSecond = v.ResponseCount / statsTimer
		}
		mCachedItemsPadlock.Unlock()
	}
	return nil
}

func sortByColumn() CachedResponsesSorted {
	mCachedItemsPadlock.Lock()
	pl := make(CachedResponsesSorted, len(mCachedItems))
	i := 0
	for k, v := range mCachedItems {
		so := SortObject{Key: k}
		switch columnSortBy {
		case SortBandwidth:
			so.Value = v.Size * v.ResponsesPerSecond
		case SortReq:
			so.Value = v.RequestCount
		case SortReqPerSec:
			so.Value = v.RequestsPerSecond
		case SortResp:
			so.Value = v.ResponseCount
		case SortRespPerSec:
			so.Value = v.ResponsesPerSecond
		case SortSize:
			so.Value = v.Size
		}
		pl[i] = so
		i++
	}
	mCachedItemsPadlock.Unlock()

	if columnSortType == SortTypeAscending {
		sort.Sort(pl)
	} else {
		sort.Sort(sort.Reverse(pl))
	}

	return pl
}

func paintHeader(g *gocui.Gui) error {
	v, err := g.View("h_keys")
	if err != nil {
		return err
	}
	v.Clear()
	v.BgColor = gocui.ColorBlue
	v.FgColor = gocui.ColorWhite
	fmt.Fprintln(v, "memcached key")

	v, err = g.View("h_req")
	if err != nil {
		return err
	}
	v.Clear()
	v.BgColor = gocui.ColorBlue
	v.FgColor = gocui.ColorWhite
	fmt.Fprintln(v, " requests")

	v, err = g.View("h_reqps")
	if err != nil {
		return err
	}
	v.Clear()
	v.BgColor = gocui.ColorBlue
	v.FgColor = gocui.ColorWhite
	fmt.Fprintln(v, "  req/sec")

	v, err = g.View("h_res")
	if err != nil {
		return err
	}
	v.Clear()
	v.BgColor = gocui.ColorBlue
	v.FgColor = gocui.ColorWhite
	fmt.Fprintln(v, " responses")

	v, err = g.View("h_resps")
	if err != nil {
		return err
	}
	v.Clear()
	v.BgColor = gocui.ColorBlue
	v.FgColor = gocui.ColorWhite
	fmt.Fprintln(v, " resp/sec")

	v, err = g.View("h_size")
	if err != nil {
		return err
	}
	v.Clear()
	v.BgColor = gocui.ColorBlue
	v.FgColor = gocui.ColorWhite
	fmt.Fprintln(v, "   size")

	v, err = g.View("h_bw")
	if err != nil {
		return err
	}
	v.Clear()
	v.BgColor = gocui.ColorBlue
	v.FgColor = gocui.ColorWhite
	fmt.Fprintln(v, "  bw(kbps)")

	return nil
}

func paintStatus(g *gocui.Gui) error {
	v, err := g.View("status")
	if err != nil {
		return err
	}
	v.Clear()
	v.BgColor = gocui.ColorRed
	v.FgColor = gocui.ColorWhite
	status := "Sort mode: "
	switch columnSortBy {
	case SortBandwidth:
		status += "bandwidth "
	case SortReq:
		status += "# of requests "
	case SortReqPerSec:
		status += "requests per sec "
	case SortResp:
		status += "# of responses "
	case SortRespPerSec:
		status += "responses per sec "
	case SortSize:
		status += "object size "
	}

	switch columnSortType {
	case SortTypeDescending:
		status += "(desc)"
	case SortTypeAscending:
		status += "(asc)"
	}

	status += fmt.Sprintf("      cache keys seen: %d", len(mCachedItems))
	status += "      (d: dump stats to local JSON file on exit - currently "
	if statsWriteToFile {
		status += "set to save stats)"
	} else {
		status += "not set to save stats)"
	}

	fmt.Fprintln(v, status)
	fmt.Fprintln(v, "b: sort by bandwidth | r: sort by requests | R: sort by req/sec | e: sort by response | E: sort by resp/sec  | q: quit | s: sort by size | t: toggle sort order")
	return nil
}

func layout(g *gocui.Gui) error {
	maxX, maxY := g.Size()
	if _, err := g.SetView("h_keys", -1, -1, maxX-(ColumnWidth*6), 1); err != nil && err != gocui.ErrUnknownView {
		return err
	}
	if _, err := g.SetView("h_req", maxX-(ColumnWidth*6), -1, maxX, 1); err != nil && err != gocui.ErrUnknownView {
		return err
	}
	if _, err := g.SetView("h_reqps", maxX-(ColumnWidth*5), -1, maxX, 1); err != nil && err != gocui.ErrUnknownView {
		return err
	}
	if _, err := g.SetView("h_res", maxX-(ColumnWidth*4), -1, maxX, 1); err != nil && err != gocui.ErrUnknownView {
		return err
	}
	if _, err := g.SetView("h_resps", maxX-(ColumnWidth*3), -1, maxX, 1); err != nil && err != gocui.ErrUnknownView {
		return err
	}
	if _, err := g.SetView("h_size", maxX-(ColumnWidth*2), -1, maxX, 1); err != nil && err != gocui.ErrUnknownView {
		return err
	}
	if _, err := g.SetView("h_bw", maxX-ColumnWidth, -1, maxX, 1); err != nil && err != gocui.ErrUnknownView {
		return err
	}

	if _, err := g.SetView("keys", -1, 1, maxX-(ColumnWidth*6), maxY-3); err != nil && err != gocui.ErrUnknownView {
		return err
	}
	if _, err := g.SetView("req", maxX-(ColumnWidth*6), 1, maxX, maxY-3); err != nil && err != gocui.ErrUnknownView {
		return err
	}
	if _, err := g.SetView("reqps", maxX-(ColumnWidth*5), 1, maxX, maxY-3); err != nil && err != gocui.ErrUnknownView {
		return err
	}
	if _, err := g.SetView("res", maxX-(ColumnWidth*4), 1, maxX, maxY-3); err != nil && err != gocui.ErrUnknownView {
		return err
	}
	if _, err := g.SetView("resps", maxX-(ColumnWidth*3), 1, maxX, maxY-3); err != nil && err != gocui.ErrUnknownView {
		return err
	}
	if _, err := g.SetView("size", maxX-(ColumnWidth*2), 1, maxX, maxY-3); err != nil && err != gocui.ErrUnknownView {
		return err
	}
	if _, err := g.SetView("bw", maxX-ColumnWidth, 1, maxX, maxY-3); err != nil && err != gocui.ErrUnknownView {
		return err
	}
	if _, err := g.SetView("status", -1, maxY-3, maxX, maxY); err != nil && err != gocui.ErrUnknownView {
		return err
	}
	return nil
}

func setUpKeyEvents(g *gocui.Gui) {
	if err := g.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, quit); err != nil {
		log.Panicln(err)
	}
	if err := g.SetKeybinding("", 'q', gocui.ModNone, quit); err != nil {
		log.Panicln(err)
	}

	g.SetKeybinding("", 'b', gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		if SortBandwidth != columnSortBy {
			columnSortBy = SortBandwidth
			paintStatus(g)
		}
		return nil
	})
	g.SetKeybinding("", 'r', gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		if SortReq != columnSortBy {
			columnSortBy = SortReq
			paintStatus(g)
		}
		return nil
	})
	g.SetKeybinding("", 'R', gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		if SortReqPerSec != columnSortBy {
			columnSortBy = SortReqPerSec
			paintStatus(g)
		}
		return nil
	})
	g.SetKeybinding("", 'e', gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		if SortResp != columnSortBy {
			columnSortBy = SortResp
			paintStatus(g)
		}
		return nil
	})
	g.SetKeybinding("", 'E', gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		if SortRespPerSec != columnSortBy {
			columnSortBy = SortRespPerSec
			paintStatus(g)
		}
		return nil
	})
	g.SetKeybinding("", 's', gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		if SortSize != columnSortBy {
			columnSortBy = SortSize
			paintStatus(g)
		}
		return nil
	})
	g.SetKeybinding("", 't', gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		if SortTypeAscending == columnSortType {
			columnSortType = SortTypeDescending
		} else {
			columnSortType = SortTypeAscending
		}
		paintStatus(g)
		return nil
	})
	g.SetKeybinding("", 'd', gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		statsWriteToFile = !statsWriteToFile
		paintStatus(g)
		return nil
	})
}

func quit(g *gocui.Gui, v *gocui.View) error {
	pprof.StopCPUProfile()

	if statsWriteToFile {
		log.Println("saving stats to disk...")
		statsWriteToFile = false
		mCachedItemsPadlock.Lock()
		stats, err := json.Marshal(mCachedItems)
		mCachedItemsPadlock.Unlock()
		if nil != err {
			log.Fatalf("error parsing the stats map: %s\n", err.Error())
		}

		cleanTime := strings.Replace(strings.Replace(strings.Replace(
			time.Now().Format("2006-01-02T15:04:05"), "T", "_", -1), ":", "", -1), "-", "", -1)

		backupFileName := fmt.Sprintf("./%s-stats.json", cleanTime)

		f, err := os.OpenFile(backupFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
		if nil != err {
			log.Fatalf("error creating the stats json file: %s\n", err.Error())
		}
		defer f.Close()

		written, err := f.Write(stats)
		if nil != err || written != len(stats) {
			log.Fatalf("error saving the stats to the json file: %s\n", err.Error())
		} else {
			log.Printf("stats written to %s\n", backupFileName)
		}
	}
	return gocui.ErrQuit
}

func getInterfaceAddresses(nic string) (string, string, error) {
	iface, err := net.InterfaceByName(nic)
	if nil != err {
		return "", "", err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", "", err
	}

	if 0 == len(addrs) {
		return "", "", errors.New("No addresses configured on the interface")
	}

	for k, addr := range addrs {
		fmt.Printf("Interface Address #%v : %v : %v\n", k, addr.String(), addr.Network())
	}

	return "", "", err
}

func Run(src gopacket.PacketDataSource) {
	var dec gopacket.Decoder
	var ok bool

	if dec, ok = gopacket.DecodersByLayerName["Ethernet"]; !ok {
		log.Fatalln("Failed to set the Ethernet decoder")
	}
	source := gopacket.NewPacketSource(src, dec)
	source.Lazy = false
	source.NoCopy = true
	source.DecodeStreamsAsDatagrams = true

	var data string
	for packet := range source.Packets() {
		// "get \S{1}" == 73, so nothing smaller than this is worth processing
		if 73 > len(packet.Data()) {
			continue
		}

		layer := packet.Layer(44) // LayerTypeTCP
		if nil == layer || 5 > len(layer.LayerPayload()) {
			continue
		}

		data = string(layer.LayerPayload())

		matches := payloadRequest.FindStringSubmatch(data)
		if 2 == len(matches) {
			mCachedItemsPadlock.Lock()
			_, exists := mCachedItems[matches[1]]
			mCachedItemsPadlock.Unlock()
			if !exists {
				nr := CachedItem{}
				nr.Size = -1
				nr.RequestCount = 1
				nr.ResponseCount = 0
				mCachedItemsPadlock.Lock()
				mCachedItems[matches[1]] = &nr
				mCachedItemsPadlock.Unlock()
			} else {
				mCachedItemsPadlock.Lock()
				mCachedItems[matches[1]].RequestCount++
				mCachedItemsPadlock.Unlock()
			}
			continue
		}

		matches = payloadResponse.FindStringSubmatch(data)
		if 3 == len(matches) {
			size, err := strconv.ParseFloat(matches[2], 32)
			if nil != err {
				continue
			}
			mCachedItemsPadlock.Lock()
			_, exists := mCachedItems[matches[1]]
			mCachedItemsPadlock.Unlock()
			if !exists {
				nr := CachedItem{}
				nr.Size = float32(size)
				nr.RequestCount = 0
				nr.ResponseCount = 1
				mCachedItemsPadlock.Lock()
				mCachedItems[matches[1]] = &nr
				mCachedItemsPadlock.Unlock()
			} else {
				mCachedItemsPadlock.Lock()
				mCachedItems[matches[1]].ResponseCount++
				mCachedItems[matches[1]].Size = float32(size)
				mCachedItemsPadlock.Unlock()
			}
			continue
		}
	}
}
