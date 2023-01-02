package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/loader"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
)

type Runner struct{}

func (r *Runner) GetResources() []map[string]string {
	return []map[string]string{
		{"instance_type": "t2.micro"},
		{"instance_type": "t2.nano"},
	}
}

func (r *Runner) GetHCLResources() *hclext.BodyContent {
	return &hclext.BodyContent{
		Blocks: []*hclext.Block{
			{
				Type:   "resource",
				Labels: []string{"aws_instance", "foo"},
				Body: &hclext.BodyContent{
					Attributes: hclext.Attributes{
						"instance_type": &hclext.Attribute{
							Name: "instance_type",
							Expr: hcl.StaticExpr(cty.StringVal("t2.micro"), hcl.Range{}),
						},
					},
				},
				DefRange: hcl.Range{Start: hcl.Pos{Line: 1}, End: hcl.Pos{Line: 1}},
			},
			{
				Type:   "resource",
				Labels: []string{"aws_instance", "bar"},
				Body: &hclext.BodyContent{
					Attributes: hclext.Attributes{
						"instance_type": &hclext.Attribute{
							Name: "instance_type",
							Expr: hcl.StaticExpr(cty.StringVal("t2.nano"), hcl.Range{}),
						},
					},
				},
				DefRange: hcl.Range{Start: hcl.Pos{Line: 2}, End: hcl.Pos{Line: 2}},
			},
		},
	}
}

func toResources(in *hclext.BodyContent) []map[string]interface{} {
	ret := make([]map[string]interface{}, len(in.Blocks))

	for i, block := range in.Blocks {
		ret[i] = map[string]interface{}{
			"config":    toData(block.Body),
			"def_range": block.DefRange,
		}
	}

	return ret
}

func toData(in *hclext.BodyContent) map[string]interface{} {
	ret := map[string]interface{}{}

	for _, attr := range in.Attributes {
		value, err := attr.Expr.Value(nil)
		if err != nil {
			panic(err)
		}

		var val string
		if err := gocty.FromCtyValue(value, &val); err != nil {
			panic(err)
		}

		ret[attr.Name] = val
	}

	for _, block := range in.Blocks {
		switch r := ret[block.Type].(type) {
		case nil:
			ret[block.Type] = []map[string]interface{}{
				{
					"config":    toData(block.Body),
					"def_range": block.DefRange,
				},
			}
		case []map[string]interface{}:
			ret[block.Type] = append(r, map[string]interface{}{
				"config":    toData(block.Body),
				"def_range": block.DefRange,
			})
		default:
			panic(fmt.Sprintf("unknown type: %T", ret[block.Type]))
		}
	}

	return ret
}

type Schema struct {
	InstanceType   string `json:"instance_type"`
	EBSBlockDevice struct {
		VolumeSize string `json:"volume_size"`
	} `json:"ebs_block_device"`
}

func toSchema(in map[string]interface{}) *hclext.BodySchema {
	schema := &hclext.BodySchema{}

	for k, v := range in {
		switch cv := v.(type) {
		case string:
			schema.Attributes = append(schema.Attributes, hclext.AttributeSchema{Name: k})
		case map[string]interface{}:
			schema.Blocks = append(schema.Blocks, hclext.BlockSchema{
				Type: k,
				Body: toSchema(cv),
			})
		default:
			panic(fmt.Sprintf("unknown value type: %#v", v))
		}
	}

	return schema
}

func runQuery(query string, ret *loader.Result) rego.ResultSet {
	input := struct {
		User string `json:"user"`
	}{
		User: "wata727",
	}

	runner := &Runner{}

	store, err := ret.Store()
	if err != nil {
		panic(err)
	}

	regoOpts := []func(*rego.Rego){
		rego.Input(input),
		rego.Store(store),
		rego.Function2(
			&rego.Function{
				Name: "terraform.resources",
				Decl: types.NewFunction(
					types.Args(
						types.S,
						types.NewObject(nil, types.NewDynamicProperty(types.S, types.A)),
					),
					types.NewObject(nil, types.NewDynamicProperty(types.S, types.A)),
				),
			},
			func(_ rego.BuiltinContext, a *ast.Term, b *ast.Term) (*ast.Term, error) {
				var resourceType string
				if err := ast.As(a.Value, &resourceType); err != nil {
					return nil, err
				}
				fmt.Printf("args: resource_type=%s\n", resourceType)
				var schema map[string]interface{}
				if err := ast.As(b.Value, &schema); err != nil {
					return nil, err
				}
				fmt.Printf("args: schema=%#v\n", toSchema(schema))

				v, err := ast.InterfaceToValue(toResources(runner.GetHCLResources()))
				if err != nil {
					return nil, err
				}
				fmt.Println("\ninput:")
				fmt.Println(v)

				return ast.NewTerm(v), nil
			},
		),
	}

	for _, m := range ret.ParsedModules() {
		regoOpts = append(regoOpts, rego.ParsedModule(m))
	}

	regoOpts = append(regoOpts, rego.Query(query))

	q := rego.New(regoOpts...)

	rs, err := q.Eval(context.Background())
	if err != nil {
		panic(err)
	}

	return rs
}

func main() {
	ret, err := loader.NewFileLoader().Filtered([]string{"policies"}, nil)
	if err != nil {
		panic(err)
	}

	rules := []string{}
	for _, m := range ret.ParsedModules() {
		for _, rule := range m.Rules {
			rules = append(rules, rule.Head.Name.String())
		}
	}

	for _, rule := range rules {
		if !strings.HasPrefix(rule, "deny_") {
			continue
		}

		fmt.Printf("---------- rule: %s----------\n", rule)

		rs := runQuery(fmt.Sprintf("data.tflint.%s", rule), ret)

		fmt.Println("\nresult:")

		for _, expr := range rs[0].Expressions {
			for _, value := range expr.Value.([]interface{}) {
				fmt.Println(value)
			}
		}
	}
}
