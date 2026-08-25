package harness

import (
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// assertGraph checks node presence, absence, state, cardinality and parentage.
//
// Every check is expressed in terms a scenario passed in — a step name, a state,
// a failure class. The harness never decides which steps ought to exist for a
// service, because that is exactly the knowledge it must not hold.
func assertGraph(t T, s Subject, e Expectation) {
	t.Helper()
	graph := s.Report.Graph()

	for _, want := range e.Nodes {
		nodes := nodesAt(graph, want.Step)
		if len(nodes) == 0 {
			t.Errorf("%s: no node at %s, want %s/%s.\n\nSteps present: %v",
				s.label(), want.Step, want.State, want.FailureClass, stepsOf(graph))
			continue
		}
		// A step measured on several paths is normal — one address each. The
		// expectation holds if some node matches, and the message shows every
		// candidate when none does.
		if matchingNode(nodes, want) {
			continue
		}
		t.Errorf("%s: no node at %s is %s/%s.\n\nObserved at that step: %s",
			s.label(), want.Step, want.State, want.FailureClass, describe(nodes))
	}

	for _, step := range e.AbsentSteps {
		if n := len(nodesAt(graph, step)); n != 0 {
			t.Errorf("%s: %d node(s) at %s, want none.\n\n"+
				"A step that must not exist is a claim svcdoctor must not make: "+
				"the run either never reached it or was never allowed to.",
				s.label(), n, step)
		}
	}

	for step, want := range e.NodeCounts {
		if got := len(nodesAt(graph, step)); got != want {
			t.Errorf("%s: %d node(s) at %s, want %d", s.label(), got, step, want)
		}
	}

	for _, edge := range e.Edges {
		if !hasEdge(graph, edge) {
			t.Errorf("%s: no %s node has a %s parent.\n\n"+
				"The relationship is the claim: a step's parent is what svcdoctor "+
				"established before it.", s.label(), edge.Child, edge.Parent)
		}
	}
}

func matchingNode(nodes []domain.Evidence, want Node) bool {
	for _, node := range nodes {
		if node.State() == want.State && node.FailureClass() == want.FailureClass {
			return true
		}
	}
	return false
}

func nodesAt(g domain.Graph, step domain.Step) []domain.Evidence {
	var out []domain.Evidence
	for _, node := range g.Nodes() {
		if node.Step() == step {
			out = append(out, node)
		}
	}
	return out
}

// hasEdge reports whether any node at edge.Child has a parent at edge.Parent.
func hasEdge(g domain.Graph, edge Edge) bool {
	for _, child := range nodesAt(g, edge.Child) {
		for _, id := range g.Parents(child.ID()) {
			parent, ok := g.Node(id)
			if ok && parent.Step() == edge.Parent {
				return true
			}
		}
	}
	return false
}

// describe renders nodes as state/class pairs.
//
// It deliberately shows the step, the state and the class and nothing else. A
// node's attributes can carry an identity or a peer-supplied value, and a
// failure message is not a place to widen what leaves the report.
func describe(nodes []domain.Evidence) string {
	out := ""
	for i, node := range nodes {
		if i > 0 {
			out += ", "
		}
		out += node.State().String() + "/" + node.FailureClass().String()
	}
	return out
}

// stepsOf lists the distinct steps present, in graph order, to make a missing
// node diagnosable without dumping the report.
func stepsOf(g domain.Graph) []domain.Step {
	seen := map[domain.Step]bool{}
	var out []domain.Step
	for _, node := range g.Nodes() {
		if seen[node.Step()] {
			continue
		}
		seen[node.Step()] = true
		out = append(out, node.Step())
	}
	return out
}
