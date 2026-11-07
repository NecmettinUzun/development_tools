package tr.com.argela.nspm;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.DoubleSummaryStatistics;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class GcLogAnalyzer {
    private static final Pattern UNIFIED_TOTAL_PATTERN = Pattern.compile(
            "(?i)(?:Heap|Metaspace)\\s*:?\\s*([0-9]+(?:[.,][0-9]+)?)([KMGT])\\(([^)]*)\\)\\s*->\\s*([0-9]+(?:[.,][0-9]+)?)([KMGT])\\(([^)]*)\\)"
    );
    private static final Pattern LEGACY_TOTAL_PATTERN = Pattern.compile(
            "(?i)([0-9]+(?:[.,][0-9]+)?)([KMGT])\\s*->\\s*([0-9]+(?:[.,][0-9]+)?)([KMGT])\\s*\\(([0-9]+(?:[.,][0-9]+)?)([KMGT])\\)"
    );
    private static final Pattern SECONDS_PATTERN = Pattern.compile("(?<![A-Za-z])([0-9]+(?:[.,][0-9]+)?):");
    private static final Pattern BRACKET_SECONDS_PATTERN = Pattern.compile("\\[([0-9]+(?:[.,][0-9]+)?)s]");
    private static final Pattern ISO_OFFSET_PATTERN = Pattern.compile(
            "(\\d{4})-(\\d{2})-(\\d{2})T(\\d{2}):(\\d{2}):(\\d{2})(?:[.,](\\d+))?([+-]\\d{2}):?(\\d{2})?"
    );
    private static final int MAX_SAMPLES = 10_000;

    private GcLogAnalyzer() {
    }

    static Analysis analyze(String logContent) {
        if (logContent == null || logContent.isBlank()) {
            throw new IllegalArgumentException("GC log file is empty.");
        }

        List<Sample> samples = new ArrayList<>();
        String[] lines = logContent.split("\\R");
        double[] firstIsoEpochSeconds = {Double.NaN};

        for (int index = 0; index < lines.length; index++) {
            Optional<MemoryReading> reading = parseReading(lines[index]);
            if (reading.isEmpty()) {
                continue;
            }

            double time = parseTimeSeconds(lines[index], firstIsoEpochSeconds).orElse((double) index);
            samples.add(new Sample(samples.size() + 1, time, reading.get().beforeMb(), reading.get().afterMb(), reading.get().committedMb()));
            if (samples.size() >= MAX_SAMPLES) {
                break;
            }
        }

        if (samples.isEmpty()) {
            throw new IllegalArgumentException("No GC memory events found. Upload a Java GC log containing heap before/after values.");
        }

        ensureStrictlyIncreasingTime(samples);

        Summary summary = summarize(samples, lines.length);
        return new Analysis(summary, samples);
    }

    private static void ensureStrictlyIncreasingTime(List<Sample> samples) {
        for (int index = 1; index < samples.size(); index++) {
            Sample previous = samples.get(index - 1);
            Sample current = samples.get(index);
            if (current.timeSeconds() <= previous.timeSeconds()) {
                samples.set(index, new Sample(
                        current.index(),
                        previous.timeSeconds() + 0.0005,
                        current.beforeMb(),
                        current.afterMb(),
                        current.committedMb()
                ));
            }
        }
    }

    private static Optional<MemoryReading> parseReading(String line) {
        Optional<MemoryReading> unified = parseUnifiedReading(line);
        if (unified.isPresent()) {
            return unified;
        }
        return parseLegacyReading(line);
    }

    private static Optional<MemoryReading> parseUnifiedReading(String line) {
        Matcher matcher = UNIFIED_TOTAL_PATTERN.matcher(line);
        MemoryReading best = null;
        while (matcher.find()) {
            double before = toMb(matcher.group(1), matcher.group(2));
            double after = toMb(matcher.group(4), matcher.group(5));
            double committed = parseCommittedMb(matcher.group(6), matcher.group(5)).orElse(Math.max(before, after));
            MemoryReading reading = new MemoryReading(before, after, committed);
            if (best == null || reading.committedMb() > best.committedMb()) {
                best = reading;
            }
        }
        return Optional.ofNullable(best);
    }

    private static Optional<MemoryReading> parseLegacyReading(String line) {
        Matcher matcher = LEGACY_TOTAL_PATTERN.matcher(line);
        MemoryReading best = null;
        while (matcher.find()) {
            double before = toMb(matcher.group(1), matcher.group(2));
            double after = toMb(matcher.group(3), matcher.group(4));
            double committed = toMb(matcher.group(5), matcher.group(6));
            MemoryReading reading = new MemoryReading(before, after, committed);
            if (best == null || reading.committedMb() > best.committedMb()) {
                best = reading;
            }
        }
        return Optional.ofNullable(best);
    }

    private static Optional<Double> parseCommittedMb(String committedText, String fallbackUnit) {
        Matcher matcher = Pattern.compile("([0-9]+(?:[.,][0-9]+)?)([KMGT]?)", Pattern.CASE_INSENSITIVE).matcher(committedText);
        Double last = null;
        while (matcher.find()) {
            String unit = matcher.group(2).isBlank() ? fallbackUnit : matcher.group(2);
            last = toMb(matcher.group(1), unit);
        }
        return Optional.ofNullable(last);
    }

    private static Optional<Double> parseTimeSeconds(String line, double[] firstIsoEpochSeconds) {
        String withoutIsoTimestamp = ISO_OFFSET_PATTERN.matcher(line).replaceAll(" ");

        Matcher bracketSecondsMatcher = BRACKET_SECONDS_PATTERN.matcher(withoutIsoTimestamp);
        if (bracketSecondsMatcher.find()) {
            return Optional.of(parseNumber(bracketSecondsMatcher.group(1)));
        }

        Matcher secondsMatcher = SECONDS_PATTERN.matcher(withoutIsoTimestamp);
        if (secondsMatcher.find()) {
            return Optional.of(parseNumber(secondsMatcher.group(1)));
        }

        Optional<Double> isoEpochSeconds = parseIsoEpochSeconds(line);
        if (isoEpochSeconds.isPresent()) {
            if (Double.isNaN(firstIsoEpochSeconds[0])) {
                firstIsoEpochSeconds[0] = isoEpochSeconds.get();
            }
            return Optional.of(isoEpochSeconds.get() - firstIsoEpochSeconds[0]);
        }

        return Optional.empty();
    }

    private static Optional<Double> parseIsoEpochSeconds(String line) {
        Matcher matcher = ISO_OFFSET_PATTERN.matcher(line);
        if (!matcher.find()) {
            return Optional.empty();
        }

        try {
            int year = Integer.parseInt(matcher.group(1));
            int month = Integer.parseInt(matcher.group(2));
            int day = Integer.parseInt(matcher.group(3));
            int hour = Integer.parseInt(matcher.group(4));
            int minute = Integer.parseInt(matcher.group(5));
            int second = Integer.parseInt(matcher.group(6));
            String fraction = matcher.group(7);
            double nanos = 0.0;
            if (fraction != null && !fraction.isBlank()) {
                nanos = Double.parseDouble("0." + fraction);
            }

            int offsetHour = Integer.parseInt(matcher.group(8));
            int offsetMinute = matcher.group(9) != null ? Integer.parseInt(matcher.group(9)) : 0;
            int offsetSign = offsetHour < 0 ? -1 : 1;
            java.time.ZoneOffset offset = java.time.ZoneOffset.ofHoursMinutes(offsetHour, offsetSign * offsetMinute);

            java.time.OffsetDateTime dateTime = java.time.OffsetDateTime.of(
                    year, month, day, hour, minute, second, 0, offset
            );
            return Optional.of(dateTime.toEpochSecond() + nanos);
        } catch (RuntimeException exception) {
            return Optional.empty();
        }
    }

    private static Summary summarize(List<Sample> samples, int lineCount) {
        DoubleSummaryStatistics beforeStats = samples.stream()
                .mapToDouble(Sample::beforeMb)
                .summaryStatistics();
        DoubleSummaryStatistics afterStats = samples.stream()
                .mapToDouble(Sample::afterMb)
                .summaryStatistics();
        double maxCommitted = samples.stream()
                .map(Sample::committedMb)
                .max(Comparator.naturalOrder())
                .orElse(0.0);
        double totalReclaimed = samples.stream()
                .mapToDouble(sample -> Math.max(0.0, sample.beforeMb() - sample.afterMb()))
                .sum();
        Sample peakBefore = samples.stream()
                .max(Comparator.comparingDouble(Sample::beforeMb))
                .orElseThrow();
        Sample lowestAfter = samples.stream()
                .min(Comparator.comparingDouble(Sample::afterMb))
                .orElseThrow();

        return new Summary(
                lineCount,
                samples.size(),
                round(beforeStats.getMin()),
                round(beforeStats.getMax()),
                round(afterStats.getMin()),
                round(afterStats.getMax()),
                round(maxCommitted),
                round(totalReclaimed),
                peakBefore.index(),
                lowestAfter.index()
        );
    }

    private static double toMb(String value, String unit) {
        double number = parseNumber(value);
        return switch (unit.toUpperCase(Locale.ROOT)) {
            case "K" -> number / 1024.0;
            case "G" -> number * 1024.0;
            case "T" -> number * 1024.0 * 1024.0;
            default -> number;
        };
    }

    private static double parseNumber(String value) {
        return Double.parseDouble(value.replace(',', '.'));
    }

    private static double round(double value) {
        return Math.round(value * 100.0) / 100.0;
    }

    private static double roundTime(double value) {
        return Math.round(value * 10_000.0) / 10_000.0;
    }

    static String toJson(Analysis analysis) {
        StringBuilder json = new StringBuilder();
        Summary summary = analysis.summary();
        json.append("{\"summary\":{")
                .append("\"lineCount\":").append(summary.lineCount()).append(',')
                .append("\"sampleCount\":").append(summary.sampleCount()).append(',')
                .append("\"minBeforeMb\":").append(summary.minBeforeMb()).append(',')
                .append("\"maxBeforeMb\":").append(summary.maxBeforeMb()).append(',')
                .append("\"minAfterMb\":").append(summary.minAfterMb()).append(',')
                .append("\"maxAfterMb\":").append(summary.maxAfterMb()).append(',')
                .append("\"totalMemoryMb\":").append(summary.totalMemoryMb()).append(',')
                .append("\"totalReclaimedMb\":").append(summary.totalReclaimedMb()).append(',')
                .append("\"peakBeforeSample\":").append(summary.peakBeforeSample()).append(',')
                .append("\"lowestAfterSample\":").append(summary.lowestAfterSample())
                .append("},\"samples\":[");

        for (int index = 0; index < analysis.samples().size(); index++) {
            Sample sample = analysis.samples().get(index);
            if (index > 0) {
                json.append(',');
            }
            json.append('{')
                    .append("\"index\":").append(sample.index()).append(',')
                    .append("\"timeSeconds\":").append(roundTime(sample.timeSeconds())).append(',')
                    .append("\"beforeMb\":").append(round(sample.beforeMb())).append(',')
                    .append("\"afterMb\":").append(round(sample.afterMb())).append(',')
                    .append("\"committedMb\":").append(round(sample.committedMb()))
                    .append('}');
        }

        json.append("]}");
        return json.toString();
    }

    record Analysis(Summary summary, List<Sample> samples) {
    }

    record Summary(
            int lineCount,
            int sampleCount,
            double minBeforeMb,
            double maxBeforeMb,
            double minAfterMb,
            double maxAfterMb,
            double totalMemoryMb,
            double totalReclaimedMb,
            int peakBeforeSample,
            int lowestAfterSample
    ) {
    }

    record Sample(int index, double timeSeconds, double beforeMb, double afterMb, double committedMb) {
    }

    private record MemoryReading(double beforeMb, double afterMb, double committedMb) {
    }
}
