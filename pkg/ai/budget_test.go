package ai

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestBudgetRejectsNegativeUsage(t *testing.T) {
	b := NewBudgetTracker(1, 10)
	if err := b.RecordUsage("test", -1, 0); err == nil {
		t.Fatal("accepted negative usage")
	}
	if b.dailySpend != 0 {
		t.Fatal("changed spend")
	}
}

func TestConcurrentBudgetRollover(t *testing.T) {
	b := NewBudgetTracker(1, 10)
	b.lastReset = time.Now().Add(-48 * time.Hour)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.CheckBudget(context.Background())
			b.GetStats()
			b.RecordUsage("test", 1, 1)
		}()
	}
	wg.Wait()
	if b.modelCosts["test"].RequestCount != 20 {
		t.Fatal("lost usage")
	}
}
