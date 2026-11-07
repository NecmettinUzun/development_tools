package tr.com.argela.nspm;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GcLogAnalyzerTest {
    @Test
    void analyzesUnifiedGcHeapLines() {
        String log = """
                [0.120s][info][gc,heap] GC(0) Heap: 40M(256M)->12M(256M)
                [1.250s][info][gc,heap] GC(1) Heap: 100M(256M)->30M(256M)
                """;

        GcLogAnalyzer.Analysis analysis = GcLogAnalyzer.analyze(log);

        assertEquals(2, analysis.summary().sampleCount());
        assertEquals(12.0, analysis.summary().minAfterMb());
        assertEquals(100.0, analysis.summary().maxBeforeMb());
        assertEquals(256.0, analysis.summary().totalMemoryMb());
        assertEquals(98.0, analysis.summary().totalReclaimedMb());
        assertEquals(2, analysis.summary().peakBeforeSample());
        assertEquals(0.12, analysis.samples().getFirst().timeSeconds(), 0.001);
    }

    @Test
    void analyzesLegacyHotSpotLines() {
        String log = """
                0.456: [GC (Allocation Failure) [PSYoungGen: 65536K->10752K(76288K)] 120000K->64000K(251392K), 0.0100000 secs]
                2.000: [Full GC (Ergonomics) [PSYoungGen: 20480K->0K(76288K)] [ParOldGen: 130000K->90000K(175104K)] 150480K->90000K(251392K), 0.1200000 secs]
                """;

        GcLogAnalyzer.Analysis analysis = GcLogAnalyzer.analyze(log);

        assertEquals(2, analysis.summary().sampleCount());
        assertEquals(117.19, analysis.samples().getFirst().beforeMb(), 0.01);
        assertEquals(62.5, analysis.samples().getFirst().afterMb());
        assertEquals(245.5, analysis.summary().totalMemoryMb());
    }

    @Test
    void rejectsLogsWithoutMemoryEvents() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> GcLogAnalyzer.analyze("no gc memory details here")
        );

        assertEquals("No GC memory events found. Upload a Java GC log containing heap before/after values.", exception.getMessage());
    }

    @Test
    void serializesAnalysisAsJson() {
        GcLogAnalyzer.Analysis analysis = GcLogAnalyzer.analyze("[0.120s][info][gc,heap] GC(0) Heap: 40M(256M)->12M(256M)");

        String json = GcLogAnalyzer.toJson(analysis);

        assertTrue(json.contains("\"sampleCount\":1"));
        assertTrue(json.contains("\"beforeMb\":40.0"));
        assertTrue(json.contains("\"afterMb\":12.0"));
    }

    @Test
    void spreadsOutEventsWhenOnlyIsoTimestampDecoratorIsPresent() {
        String log = """
                [2024-09-27T14:00:00.100+0300][info][gc,heap] GC(0) Heap: 40M(256M)->12M(256M)
                [2024-09-27T14:00:01.400+0300][info][gc,heap] GC(1) Heap: 90M(256M)->20M(256M)
                [2024-09-27T14:00:03.900+0300][info][gc,heap] GC(2) Heap: 150M(256M)->35M(256M)
                """;

        GcLogAnalyzer.Analysis analysis = GcLogAnalyzer.analyze(log);

        assertEquals(3, analysis.summary().sampleCount());
        assertEquals(0.0, analysis.samples().get(0).timeSeconds(), 0.01);
        assertEquals(1.3, analysis.samples().get(1).timeSeconds(), 0.01);
        assertEquals(3.8, analysis.samples().get(2).timeSeconds(), 0.01);
    }

    @Test
    void nudgesDuplicateTimestampsSoEveryGcEventIsDistinguishable() {
        String log = """
                [2024-09-27T14:00:00+0300][info][gc,heap] GC(0) Heap: 40M(256M)->12M(256M)
                [2024-09-27T14:00:00+0300][info][gc,heap] GC(1) Heap: 90M(256M)->20M(256M)
                [2024-09-27T14:00:00+0300][info][gc,heap] GC(2) Heap: 150M(256M)->35M(256M)
                """;

        GcLogAnalyzer.Analysis analysis = GcLogAnalyzer.analyze(log);

        double first = analysis.samples().get(0).timeSeconds();
        double second = analysis.samples().get(1).timeSeconds();
        double third = analysis.samples().get(2).timeSeconds();

        assertTrue(second > first);
        assertTrue(third > second);
    }
}
