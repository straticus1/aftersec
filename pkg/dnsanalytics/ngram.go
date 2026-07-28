package dnsanalytics

import (
	"math"
	"strings"
)

type ngramModel struct {
	benign map[string]float64
	dga    map[string]float64
}

var benignTrainingDomains = []string{
	"google", "microsoft", "apple", "amazon", "cloudflare", "github", "wikipedia",
	"linkedin", "netflix", "mozilla", "ubuntu", "docker", "kubernetes", "facebook",
	"instagram", "dropbox", "slack", "stripe", "adobe", "salesforce", "wordpress",
	"stackoverflow", "nytimes", "weather", "banking", "security", "developer",
}

var dgaTrainingDomains = []string{
	"xj3k9q2m", "q7v2z8wx", "m4n8q1pk", "z9x7c3vb", "k2j8h4gf", "p9q3w7er",
	"v6b2n8mx", "r4t9y1ui", "d8f3g7hj", "l5k1j9hg", "c7v4b8nm", "w2e9r5ty",
	"qzxvbnm7", "mnbvcxz3", "a8s4d9f2", "u7i3o9p1", "h4j8k2l6", "n9m5b1v7",
}

func trainDefaultNGramModel() *ngramModel {
	return &ngramModel{
		benign: trainTrigrams(benignTrainingDomains),
		dga:    trainTrigrams(dgaTrainingDomains),
	}
}

func trainTrigrams(labels []string) map[string]float64 {
	counts := make(map[string]float64)
	total := 0.0
	for _, label := range labels {
		padded := "^^" + strings.ToLower(label) + "$"
		for i := 0; i+3 <= len(padded); i++ {
			counts[padded[i:i+3]]++
			total++
		}
	}
	vocabulary := float64(len(counts) + 1)
	for gram, count := range counts {
		counts[gram] = math.Log((count + 1) / (total + vocabulary))
	}
	counts[""] = math.Log(1 / (total + vocabulary))
	return counts
}

func (m *ngramModel) score(label string) float64 {
	if m == nil || len(label) < 4 {
		return 0
	}
	padded := "^^" + strings.ToLower(label) + "$"
	ratio := 0.0
	count := 0
	for i := 0; i+3 <= len(padded); i++ {
		gram := padded[i : i+3]
		ratio += lookupGram(m.dga, gram) - lookupGram(m.benign, gram)
		count++
	}
	if count == 0 {
		return 0
	}
	ratio /= float64(count)
	return 1 / (1 + math.Exp(-ratio))
}

func lookupGram(model map[string]float64, gram string) float64 {
	if value, ok := model[gram]; ok {
		return value
	}
	return model[""]
}
