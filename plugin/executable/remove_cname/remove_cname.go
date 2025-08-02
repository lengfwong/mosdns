/*
 * Copyright (C) 2020-2025, lengfwong
 *
 * This file is plugin of mosdns.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package remove_cname

import (
	"context"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	// "github.com/IrineSistiana/mosdns/v5/mlog"
)

const PluginType = "remove_cname"

func init() {
	// Register the plugin type and initialization function (supporting config parameters)
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })

	// Register quick setup function for easy shorthand use in sequences
	sequence.MustRegExecQuickSetup(PluginType, QuickSetup)
}

// Args defines plugin arguments. Currently empty but reserved for future expansion.
type Args struct{}

// removeCname plugin structure
type removeCname struct{}

// Ensure the plugin implements the sequence.Executable interface
var _ sequence.Executable = (*removeCname)(nil)

// Exec is the core logic of the plugin
func (p *removeCname) Exec(ctx context.Context, qCtx *query_context.Context) error {
	reqMsg := qCtx.Q()
	respMsg := qCtx.R()
	if respMsg == nil || len(respMsg.Answer) == 0 {
		return nil // If there is no response or no Answer section, return directly
	}

	// mlog.S().Debugw("[remove_cname] Plugin executing",
	//     "query", reqMsg.Question[0].Name,

	// Filter out CNAME records in the Answer section
	switch qt := reqMsg.Question[0].Qtype; qt {
	case dns.TypeA, dns.TypeAAAA:
		newAns := respMsg.Answer[:0]
		if respMsg.Answer[0].Header().Rrtype == dns.TypeCNAME {
			for _, rr := range respMsg.Answer {
				if rr.Header().Rrtype == qt {
					// Prevent the original Name from being lost after removing the CNAME
					rr.Header().Name = reqMsg.Question[0].Name
					newAns = append(newAns, rr)
				}
			}
			respMsg.Answer = newAns
		}
	}
	return nil
}

// Init is used for plugin initialization, with configuration parameters passed in
func Init(_ *coremain.BP, args any) (any, error) {
	return &removeCname{}, nil
}

// QuickSetup is for fast initialization. "remove_cname" can be directly used in sequence
func QuickSetup(_ sequence.BQ, s string) (any, error) {
	// No parameters needed, directly return an instance
	return &removeCname{}, nil
}
