package indexer

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// The server caps a request without a page at its page size. These pin the
// client to fetching every page on the caller's behalf in that case, so a
// wallet that reads only the list and never looks at the page is not handed a
// truncated set.
func TestGetVtxosPaging(t *testing.T) {
	ctx := context.Background()
	scripts := clientlib.WithScripts([]string{"0014deadbeef"})

	t.Run("a request without a page fetches every page", func(t *testing.T) {
		srv := newPagingIndexerServer(250, 100)
		c := newBufconnClient(t, srv)

		resp, err := c.GetVtxos(ctx, scripts)
		require.NoError(t, err)
		require.Len(t, resp.Vtxos, 250)
		require.Nil(t, resp.Page, "a caller that asked for no page gets none back")

		seen := make(map[string]struct{}, len(resp.Vtxos))
		for _, v := range resp.Vtxos {
			_, dup := seen[v.Txid]
			require.False(t, dup, "vtxo %s came back twice", v.Txid)
			seen[v.Txid] = struct{}{}
		}

		pages := srv.pages()
		require.Len(t, pages, 3)
		for _, p := range pages {
			require.NotNil(t, p, "every request must carry a page")
		}
	})

	t.Run("an explicit page is a single request for that page", func(t *testing.T) {
		srv := newPagingIndexerServer(250, 100)
		c := newBufconnClient(t, srv)

		resp, err := c.GetVtxos(
			ctx, scripts, clientlib.WithVtxosPage(&clientlib.PageRequest{Size: 100, Index: 2}),
		)
		require.NoError(t, err)
		require.Len(t, resp.Vtxos, 100)
		require.NotNil(t, resp.Page)
		require.Equal(t, int32(2), resp.Page.Current)
		require.Equal(t, int32(3), resp.Page.Total)
		require.Len(t, srv.pages(), 1)
	})
}

// pagingIndexerServer serves a fixed vtxo set in pages the way arkd does: a
// missing page is page one, a size above the cap is clamped to it, and next is
// clamped to total on the last page.
type pagingIndexerServer struct {
	arkv1.UnimplementedIndexerServiceServer
	vtxos   []*arkv1.IndexerVtxo
	maxSize int32

	mu       sync.Mutex
	requests []*arkv1.IndexerPageRequest
}

func newPagingIndexerServer(count int, maxSize int32) *pagingIndexerServer {
	vtxos := make([]*arkv1.IndexerVtxo, 0, count)
	for i := 0; i < count; i++ {
		vtxos = append(vtxos, &arkv1.IndexerVtxo{
			Outpoint: &arkv1.IndexerOutpoint{Txid: fmt.Sprintf("vtxo-%03d", i)},
			Script:   "0014deadbeef",
			Amount:   1000,
		})
	}
	return &pagingIndexerServer{vtxos: vtxos, maxSize: maxSize}
}

func (s *pagingIndexerServer) GetVtxos(
	_ context.Context, req *arkv1.GetVtxosRequest,
) (*arkv1.GetVtxosResponse, error) {
	s.mu.Lock()
	s.requests = append(s.requests, req.GetPage())
	s.mu.Unlock()

	index, size := int32(1), s.maxSize
	if p := req.GetPage(); p != nil {
		if p.GetIndex() > 0 {
			index = p.GetIndex()
		}
		if p.GetSize() > 0 && p.GetSize() < s.maxSize {
			size = p.GetSize()
		}
	}

	total := int32(len(s.vtxos))
	totalPages := (total + size - 1) / size
	start := (index - 1) * size
	items := []*arkv1.IndexerVtxo{}
	if start < total {
		items = s.vtxos[start:min(start+size, total)]
	}
	return &arkv1.GetVtxosResponse{
		Vtxos: items,
		Page: &arkv1.IndexerPageResponse{
			Current: index,
			Next:    min(index+1, totalPages),
			Total:   totalPages,
		},
	}, nil
}

func (s *pagingIndexerServer) pages() []*arkv1.IndexerPageRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*arkv1.IndexerPageRequest(nil), s.requests...)
}

func newBufconnClient(t *testing.T, srv arkv1.IndexerServiceServer) *grpcClient {
	t.Helper()

	lis := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	arkv1.RegisterIndexerServiceServer(server, srv)
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return &grpcClient{
		conn:    conn,
		connMu:  &sync.RWMutex{},
		scripts: newScriptsCache(),
	}
}
