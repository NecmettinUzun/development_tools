package tr.com.argela.nspm;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;

final class DevToolServer {
    private static final int MAX_FORM_BYTES = 2 * 1024 * 1024;
    private static final int MAX_GC_LOG_BYTES = 20 * 1024 * 1024;

    private final HttpServer server;

    private DevToolServer(HttpServer server) {
        this.server = server;
    }

    static DevToolServer start(int port) throws IOException {
        HttpServer httpServer = HttpServer.create(new InetSocketAddress(port), 0);
        DevToolServer app = new DevToolServer(httpServer);
        httpServer.createContext("/", app::handleHome);
        httpServer.createContext("/tools/hex-to-pcap", app::handleHexToPcapPage);
        httpServer.createContext("/tools/gc-log-analyzer", app::handleGcLogAnalyzerPage);
        httpServer.createContext("/api/hex-to-pcap", app::handleHexToPcapDownload);
        httpServer.createContext("/api/gc-log-analyzer", app::handleGcLogAnalyzerApi);
        httpServer.createContext("/health", app::handleHealth);
        httpServer.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        httpServer.start();
        return app;
    }

    int port() {
        return server.getAddress().getPort();
    }

    void stop(int delaySeconds) {
        server.stop(delaySeconds);
    }

    private void handleHome(HttpExchange exchange) throws IOException {
        if (!isMethod(exchange, "GET")) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }

        sendHtml(exchange, 200, """
                <!doctype html>
                <html lang="en">
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <title>Development Tools</title>
                    <style>
                        :root { color-scheme: dark; font-family: Inter, Segoe UI, Arial, sans-serif; }
                        body { margin: 0; background: #101827; color: #e5e7eb; }
                        main { max-width: 960px; margin: 0 auto; padding: 48px 24px; }
                        h1 { margin: 0 0 12px; font-size: 40px; }
                        p { color: #a7b0c0; line-height: 1.6; }
                        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin-top: 32px; }
                        .card { display: block; padding: 22px; border: 1px solid #263244; border-radius: 18px; background: #172033; color: inherit; text-decoration: none; }
                        .card:hover { border-color: #5b8cff; transform: translateY(-1px); }
                        .tag { display: inline-block; margin-top: 16px; color: #93c5fd; font-size: 14px; }
                    </style>
                </head>
                <body>
                    <main>
                        <h1>Development Tools</h1>
                        <p>Small utilities for daily engineering work. Pick a tool and run it locally in your browser.</p>
                        <section class="grid">
                            <a class="card" href="/tools/hex-to-pcap">
                                <h2>Hex to PCAP</h2>
                                <p>Convert raw packet bytes from hex text into a downloadable .pcap file for Wireshark.</p>
                                <span class="tag">Open tool →</span>
                            </a>
                            <a class="card" href="/tools/gc-log-analyzer">
                                <h2>GC Log Analyzer</h2>
                                <p>Load Java GC logs and visualize memory growth, reduction, min/max, total and used memory.</p>
                                <span class="tag">Open tool →</span>
                            </a>
                        </section>
                    </main>
                </body>
                </html>
                """);
    }

    private void handleGcLogAnalyzerPage(HttpExchange exchange) throws IOException {
        if (!isMethod(exchange, "GET")) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }

        sendHtml(exchange, 200, """
                <!doctype html>
                <html lang="en">
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <title>GC Log Analyzer</title>
                    <style>
                        :root { color-scheme: dark; font-family: Inter, Segoe UI, Arial, sans-serif; }
                        body { margin: 0; background: #101827; color: #e5e7eb; }
                        main { max-width: 1180px; margin: 0 auto; padding: 40px 24px; }
                        a { color: #93c5fd; text-decoration: none; }
                        h1 { margin: 24px 0 10px; font-size: 38px; }
                        p, label, small { color: #a7b0c0; line-height: 1.6; }
                        .panel { margin-top: 24px; padding: 24px; border: 1px solid #263244; border-radius: 20px; background: #172033; }
                        input { width: 100%; box-sizing: border-box; border: 1px solid #334155; border-radius: 12px; background: #0f172a; color: #e5e7eb; padding: 12px; font: inherit; }
                        button { margin-top: 16px; border: 0; border-radius: 12px; background: #3b82f6; color: white; padding: 12px 18px; font: inherit; font-weight: 700; cursor: pointer; }
                        button:disabled { cursor: not-allowed; opacity: .55; }
                        button.secondary { background: #334155; }
                        button.secondary:hover { background: #3f4b60; }
                        .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-top: 20px; }
                        .metric { padding: 16px; border: 1px solid #263244; border-radius: 16px; background: #0f172a; }
                        .metric small { display: block; margin-bottom: 8px; }
                        .metric strong { font-size: 24px; }
                        .chart-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 24px; flex-wrap: wrap; }
                        .chart-toolbar small { margin: 0; }
                        .chart-wrap { position: relative; width: 100%; height: 460px; margin-top: 12px; border: 1px solid #263244; border-radius: 16px; background: #0f172a; overflow: hidden; touch-action: none; }
                        .chart-wrap canvas { position: absolute; top: 0; left: 0; width: 100%; height: 100%; cursor: grab; }
                        .chart-wrap.dragging canvas { cursor: grabbing; }
                        #tooltip { position: absolute; pointer-events: none; padding: 10px 12px; border-radius: 10px; background: rgba(15, 23, 42, 0.96); border: 1px solid #334155; font-size: 13px; line-height: 1.5; white-space: nowrap; opacity: 0; transform: translate(-9999px, -9999px); transition: opacity .08s ease; }
                        #tooltip strong { color: #93c5fd; }
                        .error { color: #fecaca; background: #7f1d1d; border: 1px solid #ef4444; padding: 12px; border-radius: 12px; margin-top: 16px; }
                        .hidden { display: none; }
                    </style>
                </head>
                <body>
                    <main>
                        <a href="/">← All tools</a>
                        <h1>GC Log Analyzer</h1>
                        <p>Load a Java GC log file and inspect heap usage before/after collections, total committed memory, reclaimed memory, min/max values and a visual memory trend. Every GC event is plotted as a distinct drop on the chart.</p>

                        <section class="panel">
                            <label for="gcLog">GC log file</label>
                            <input id="gcLog" type="file" accept=".log,.txt,text/plain">
                            <small>Supports common HotSpot unified logs and older GC log lines with heap before/after values.</small>
                            <br>
                            <button id="analyze" type="button">Analyze log</button>
                            <div id="error" class="error hidden"></div>
                        </section>

                        <section id="result" class="panel hidden">
                            <h2>Summary</h2>
                            <div id="metrics" class="cards"></div>

                            <div class="chart-toolbar">
                                <small>Scroll / pinch to zoom, drag to pan, hover a point to inspect a GC event.</small>
                                <button id="resetZoom" type="button" class="secondary">Reset zoom</button>
                            </div>
                            <div id="chartWrap" class="chart-wrap">
                                <canvas id="memoryChart"></canvas>
                                <div id="tooltip"></div>
                            </div>
                        </section>
                    </main>

                    <script>
                        const fileInput = document.getElementById('gcLog');
                        const analyzeButton = document.getElementById('analyze');
                        const resetZoomButton = document.getElementById('resetZoom');
                        const errorBox = document.getElementById('error');
                        const result = document.getElementById('result');
                        const metrics = document.getElementById('metrics');
                        const chartWrap = document.getElementById('chartWrap');
                        const chart = document.getElementById('memoryChart');
                        const tooltip = document.getElementById('tooltip');
                        const context = chart.getContext('2d');

                        let dataSamples = [];
                        let fullDomain = [0, 1];
                        let viewDomain = [0, 1];
                        let isDragging = false;
                        let dragStartX = 0;
                        let dragStartDomain = [0, 1];
                        let didDrag = false;

                        analyzeButton.addEventListener('click', async () => {
                            const file = fileInput.files[0];
                            if (!file) {
                                showError('Please choose a GC log file first.');
                                return;
                            }

                            analyzeButton.disabled = true;
                            analyzeButton.textContent = 'Analyzing...';
                            hideError();

                            try {
                                const content = await file.text();
                                const response = await fetch('/api/gc-log-analyzer', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
                                    body: content
                                });
                                const payload = await response.json();
                                if (!response.ok) {
                                    throw new Error(payload.error || 'GC log could not be analyzed.');
                                }
                                render(payload);
                            } catch (error) {
                                result.classList.add('hidden');
                                showError(error.message);
                            } finally {
                                analyzeButton.disabled = false;
                                analyzeButton.textContent = 'Analyze log';
                            }
                        });

                        function render(data) {
                            const summary = data.summary;
                            metrics.innerHTML = [
                                metric('Events', summary.sampleCount),
                                metric('Total memory', mb(summary.totalMemoryMb)),
                                metric('Used min/max before GC', `${mb(summary.minBeforeMb)} / ${mb(summary.maxBeforeMb)}`),
                                metric('Used min/max after GC', `${mb(summary.minAfterMb)} / ${mb(summary.maxAfterMb)}`),
                                metric('Total reclaimed', mb(summary.totalReclaimedMb)),
                                metric('Peak before GC event', `#${summary.peakBeforeSample}`)
                            ].join('');

                            dataSamples = data.samples;
                            const times = dataSamples.map(s => s.timeSeconds);
                            const minTime = Math.min(...times);
                            const maxTime = Math.max(...times);
                            const span = Math.max(maxTime - minTime, 0.001);
                            fullDomain = [minTime - span * 0.02, maxTime + span * 0.02];
                            viewDomain = [fullDomain[0], fullDomain[1]];

                            result.classList.remove('hidden');
                            resizeCanvas();
                            drawChart();
                        }

                        function metric(label, value) {
                            return `<div class="metric"><small>${label}</small><strong>${value}</strong></div>`;
                        }

                        function resizeCanvas() {
                            const dpr = window.devicePixelRatio || 1;
                            const rect = chartWrap.getBoundingClientRect();
                            chart.width = Math.max(1, Math.round(rect.width * dpr));
                            chart.height = Math.max(1, Math.round(rect.height * dpr));
                            context.setTransform(dpr, 0, 0, dpr, 0, 0);
                        }

                        function cssSize() {
                            const dpr = window.devicePixelRatio || 1;
                            return { width: chart.width / dpr, height: chart.height / dpr };
                        }

                        function buildEventPoints() {
                            const points = [];
                            dataSamples.forEach((sample, index) => {
                                if (index > 0) {
                                    const previous = dataSamples[index - 1];
                                    points.push({ time: sample.timeSeconds, value: previous.afterMb, kind: 'growth-end', sample });
                                }
                                points.push({ time: sample.timeSeconds, value: sample.beforeMb, kind: 'before', sample });
                                points.push({ time: sample.timeSeconds, value: sample.afterMb, kind: 'after', sample });
                            });
                            return points;
                        }

                        function drawChart() {
                            const { width, height } = cssSize();
                            const padding = { left: 64, right: 24, top: 26, bottom: 34 };
                            context.clearRect(0, 0, width, height);

                            if (dataSamples.length === 0) {
                                return;
                            }

                            const [xMin, xMax] = viewDomain;
                            const visible = dataSamples.filter(s => s.timeSeconds >= xMin && s.timeSeconds <= xMax);
                            const referenceSet = visible.length > 0 ? visible : dataSamples;
                            const maxY = Math.max(...referenceSet.map(s => Math.max(s.beforeMb, s.afterMb, s.committedMb)), 1) * 1.08;

                            const toX = time => padding.left + ((width - padding.left - padding.right) * (time - xMin) / Math.max(xMax - xMin, 0.001));
                            const toY = value => height - padding.bottom - ((height - padding.top - padding.bottom) * value / maxY);

                            drawGrid(padding, width, height, xMin, xMax, maxY, toX, toY);
                            drawCommittedLine(toX, toY);
                            drawSawtooth(toX, toY);
                            drawEventMarkers(toX, toY);
                            drawLegend();
                        }

                        function drawGrid(padding, width, height, xMin, xMax, maxY, toX, toY) {
                            context.strokeStyle = '#1f2937';
                            context.fillStyle = '#a7b0c0';
                            context.font = '12px Segoe UI';

                            for (let index = 0; index <= 4; index++) {
                                const value = maxY * index / 4;
                                const y = toY(value);
                                context.beginPath();
                                context.moveTo(padding.left, y);
                                context.lineTo(width - padding.right, y);
                                context.stroke();
                                context.fillText(`${number(maxY - value)} MB`, 6, y + 4);
                            }

                            const ticks = 6;
                            for (let index = 0; index <= ticks; index++) {
                                const time = xMin + (xMax - xMin) * index / ticks;
                                const x = toX(time);
                                context.beginPath();
                                context.moveTo(x, padding.top);
                                context.lineTo(x, height - padding.bottom);
                                context.stroke();
                                context.fillText(`${number(time)}s`, x - 14, height - 12);
                            }
                        }

                        function drawCommittedLine(toX, toY) {
                            context.strokeStyle = '#64748b';
                            context.setLineDash([6, 5]);
                            context.lineWidth = 1.5;
                            context.beginPath();
                            dataSamples.forEach((sample, index) => {
                                const x = toX(sample.timeSeconds);
                                const y = toY(sample.committedMb);
                                if (index === 0) {
                                    context.moveTo(x, y);
                                } else {
                                    context.lineTo(x, y);
                                }
                            });
                            context.stroke();
                            context.setLineDash([]);
                        }

                        function drawSawtooth(toX, toY) {
                            const points = buildEventPoints();
                            if (points.length === 0) {
                                return;
                            }

                            context.lineWidth = 2;
                            for (let index = 1; index < points.length; index++) {
                                const previous = points[index - 1];
                                const current = points[index];
                                const growth = previous.kind === 'growth-end' || (previous.kind === 'after' && current.kind === 'growth-end');
                                context.strokeStyle = current.kind === 'after' ? '#ef4444' : '#f97316';
                                context.beginPath();
                                context.moveTo(toX(previous.time), toY(previous.value));
                                context.lineTo(toX(current.time), toY(current.value));
                                context.stroke();
                            }
                        }

                        function drawEventMarkers(toX, toY) {
                            const [xMin, xMax] = viewDomain;
                            dataSamples.forEach(sample => {
                                if (sample.timeSeconds < xMin || sample.timeSeconds > xMax) {
                                    return;
                                }
                                const x = toX(sample.timeSeconds);
                                drawMarker(x, toY(sample.beforeMb), '#f97316');
                                drawMarker(x, toY(sample.afterMb), '#22c55e');
                            });
                        }

                        function drawMarker(x, y, color) {
                            context.beginPath();
                            context.arc(x, y, 4, 0, Math.PI * 2);
                            context.fillStyle = color;
                            context.fill();
                            context.lineWidth = 1.5;
                            context.strokeStyle = '#0f172a';
                            context.stroke();
                        }

                        function drawLegend() {
                            const items = [
                                ['Committed / total', '#64748b'],
                                ['Used before GC', '#f97316'],
                                ['Used after GC', '#22c55e']
                            ];
                            context.font = '13px Segoe UI';
                            items.forEach((item, index) => {
                                const x = 70 + index * 170;
                                context.fillStyle = item[1];
                                context.fillRect(x, 8, 14, 14);
                                context.fillStyle = '#e5e7eb';
                                context.fillText(item[0], x + 20, 19);
                            });
                        }

                        function nearestSample(clientX, clientY) {
                            if (dataSamples.length === 0) {
                                return null;
                            }
                            const rect = chart.getBoundingClientRect();
                            const { width } = cssSize();
                            const padding = { left: 64, right: 24 };
                            const [xMin, xMax] = viewDomain;
                            const toX = time => padding.left + ((width - padding.left - padding.right) * (time - xMin) / Math.max(xMax - xMin, 0.001));

                            const mouseX = clientX - rect.left;
                            let best = null;
                            let bestDistance = Infinity;
                            dataSamples.forEach(sample => {
                                const distance = Math.abs(toX(sample.timeSeconds) - mouseX);
                                if (distance < bestDistance) {
                                    bestDistance = distance;
                                    best = sample;
                                }
                            });
                            return bestDistance <= 26 ? best : null;
                        }

                        function showTooltip(sample, clientX, clientY) {
                            const rect = chartWrap.getBoundingClientRect();
                            const reclaimed = Math.max(0, sample.beforeMb - sample.afterMb);
                            tooltip.innerHTML = `
                                <div><strong>GC #${sample.index}</strong></div>
                                <div>Time: ${number(sample.timeSeconds)} s</div>
                                <div>Before: ${mb(sample.beforeMb)}</div>
                                <div>After: ${mb(sample.afterMb)}</div>
                                <div>Reclaimed: ${mb(reclaimed)}</div>
                                <div>Total: ${mb(sample.committedMb)}</div>
                            `;
                            let left = clientX - rect.left + 16;
                            let top = clientY - rect.top + 16;
                            left = Math.min(left, rect.width - 190);
                            top = Math.min(top, rect.height - 130);
                            tooltip.style.transform = `translate(${left}px, ${top}px)`;
                            tooltip.style.opacity = '1';
                        }

                        function hideTooltip() {
                            tooltip.style.opacity = '0';
                            tooltip.style.transform = 'translate(-9999px, -9999px)';
                        }

                        function clampDomain(domain) {
                            const [fMin, fMax] = fullDomain;
                            const fullSpan = fMax - fMin;
                            let [min, max] = domain;
                            let span = Math.max(max - min, fullSpan * 0.002);
                            span = Math.min(span, fullSpan);
                            if (min < fMin) {
                                min = fMin;
                                max = min + span;
                            }
                            if (max > fMax) {
                                max = fMax;
                                min = max - span;
                            }
                            return [min, max];
                        }

                        chart.addEventListener('wheel', event => {
                            if (dataSamples.length === 0) {
                                return;
                            }
                            event.preventDefault();
                            const rect = chart.getBoundingClientRect();
                            const { width } = cssSize();
                            const padding = { left: 64, right: 24 };
                            const [xMin, xMax] = viewDomain;
                            const ratio = (event.clientX - rect.left - padding.left) / Math.max(width - padding.left - padding.right, 1);
                            const anchorTime = xMin + (xMax - xMin) * Math.min(Math.max(ratio, 0), 1);
                            const zoomFactor = event.deltaY < 0 ? 0.82 : 1.22;
                            const newSpan = (xMax - xMin) * zoomFactor;
                            const newMin = anchorTime - (anchorTime - xMin) * zoomFactor;
                            viewDomain = clampDomain([newMin, newMin + newSpan]);
                            hideTooltip();
                            drawChart();
                        }, { passive: false });

                        chart.addEventListener('mousedown', event => {
                            if (dataSamples.length === 0) {
                                return;
                            }
                            isDragging = true;
                            didDrag = false;
                            dragStartX = event.clientX;
                            dragStartDomain = [...viewDomain];
                            chartWrap.classList.add('dragging');
                        });

                        window.addEventListener('mousemove', event => {
                            if (!isDragging) {
                                if (dataSamples.length === 0) {
                                    return;
                                }
                                const rect = chart.getBoundingClientRect();
                                if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) {
                                    hideTooltip();
                                    return;
                                }
                                const sample = nearestSample(event.clientX, event.clientY);
                                if (sample) {
                                    showTooltip(sample, event.clientX, event.clientY);
                                } else {
                                    hideTooltip();
                                }
                                return;
                            }

                            const { width } = cssSize();
                            const padding = { left: 64, right: 24 };
                            const plotWidth = Math.max(width - padding.left - padding.right, 1);
                            const [dMin, dMax] = dragStartDomain;
                            const deltaTime = (event.clientX - dragStartX) / plotWidth * (dMax - dMin);
                            if (Math.abs(event.clientX - dragStartX) > 2) {
                                didDrag = true;
                            }
                            viewDomain = clampDomain([dMin - deltaTime, dMax - deltaTime]);
                            hideTooltip();
                            drawChart();
                        });

                        window.addEventListener('mouseup', () => {
                            isDragging = false;
                            chartWrap.classList.remove('dragging');
                        });

                        chart.addEventListener('mouseleave', hideTooltip);

                        resetZoomButton.addEventListener('click', () => {
                            viewDomain = [...fullDomain];
                            drawChart();
                        });

                        window.addEventListener('resize', () => {
                            if (dataSamples.length === 0) {
                                return;
                            }
                            resizeCanvas();
                            drawChart();
                        });

                        function mb(value) {
                            return `${number(value)} MB`;
                        }

                        function number(value) {
                            return Number(value).toLocaleString(undefined, { maximumFractionDigits: 2 });
                        }

                        function showError(message) {
                            errorBox.textContent = message;
                            errorBox.classList.remove('hidden');
                        }

                        function hideError() {
                            errorBox.textContent = '';
                            errorBox.classList.add('hidden');
                        }
                    </script>
                </body>
                </html>
                """);
    }

    private void handleHexToPcapPage(HttpExchange exchange) throws IOException {
        if (!isMethod(exchange, "GET")) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }

        sendHtml(exchange, 200, """
                <!doctype html>
                <html lang="en">
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <title>Hex to PCAP</title>
                    <style>
                        :root { color-scheme: dark; font-family: Inter, Segoe UI, Arial, sans-serif; }
                        body { margin: 0; background: #101827; color: #e5e7eb; }
                        main { max-width: 960px; margin: 0 auto; padding: 40px 24px; }
                        a { color: #93c5fd; text-decoration: none; }
                        h1 { margin: 24px 0 10px; font-size: 38px; }
                        p, label, small { color: #a7b0c0; line-height: 1.6; }
                        form { margin-top: 28px; padding: 24px; border: 1px solid #263244; border-radius: 20px; background: #172033; }
                        textarea, select, input { width: 100%; box-sizing: border-box; border: 1px solid #334155; border-radius: 12px; background: #0f172a; color: #e5e7eb; padding: 12px; font: inherit; }
                        textarea { min-height: 260px; resize: vertical; font-family: Consolas, Menlo, monospace; }
                        label { display: block; margin: 18px 0 8px; font-weight: 700; }
                        button { margin-top: 20px; border: 0; border-radius: 12px; background: #3b82f6; color: white; padding: 12px 18px; font: inherit; font-weight: 700; cursor: pointer; }
                        button:hover { background: #2563eb; }
                        .row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
                        @media (max-width: 720px) { .row { grid-template-columns: 1fr; } }
                    </style>
                </head>
                <body>
                    <main>
                        <a href="/">← All tools</a>
                        <h1>Hex to PCAP</h1>
                        <p>Paste raw packet bytes as hex and download a PCAP that can be opened in Wireshark. Separators like spaces, colons, dashes, commas, <code>0x</code>, and <code>\\x</code> are accepted.</p>
                        <form method="post" action="/api/hex-to-pcap">
                            <label for="hex">Packet hex</label>
                            <textarea id="hex" name="hex" required placeholder="00 11 22 33 44 55 aa bb cc dd ee ff 08 00 ..."></textarea>
                            <div class="row">
                                <div>
                                    <label for="linkType">PCAP link type</label>
                                    <select id="linkType" name="linkType">
                                        <option value="1" selected>Ethernet (DLT_EN10MB)</option>
                                        <option value="101">Raw IP (DLT_RAW)</option>
                                        <option value="113">Linux cooked capture (DLT_LINUX_SLL)</option>
                                    </select>
                                </div>
                                <div>
                                    <label for="fileName">File name</label>
                                    <input id="fileName" name="fileName" value="packet.pcap" maxlength="80">
                                </div>
                            </div>
                            <button type="submit">Download PCAP</button>
                        </form>
                    </main>
                </body>
                </html>
                """);
    }

    private void handleHexToPcapDownload(HttpExchange exchange) throws IOException {
        if (!isMethod(exchange, "POST")) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }

        try {
            Map<String, String> form = parseForm(exchange.getRequestBody(), MAX_FORM_BYTES);
            String hex = form.getOrDefault("hex", "");
            int linkType = parseLinkType(form.getOrDefault("linkType", "1"));
            String fileName = sanitizeFileName(form.getOrDefault("fileName", "packet.pcap"));
            byte[] pcap = HexToPcapTool.convert(hex, linkType, Instant.now());

            Headers headers = exchange.getResponseHeaders();
            headers.set("Content-Type", "application/vnd.tcpdump.pcap");
            headers.set("Content-Disposition", "attachment; filename=\"" + fileName + "\"");
            exchange.sendResponseHeaders(200, pcap.length);
            try (OutputStream output = exchange.getResponseBody()) {
                output.write(pcap);
            }
        } catch (IllegalArgumentException exception) {
            sendText(exchange, 400, exception.getMessage());
        }
    }

    private void handleGcLogAnalyzerApi(HttpExchange exchange) throws IOException {
        if (!isMethod(exchange, "POST")) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }

        try {
            byte[] body = exchange.getRequestBody().readNBytes(MAX_GC_LOG_BYTES + 1);
            if (body.length > MAX_GC_LOG_BYTES) {
                throw new IllegalArgumentException("GC log file is too large. Maximum size is 20 MB.");
            }
            String logContent = new String(body, StandardCharsets.UTF_8);
            GcLogAnalyzer.Analysis analysis = GcLogAnalyzer.analyze(logContent);
            sendJson(exchange, 200, GcLogAnalyzer.toJson(analysis));
        } catch (IllegalArgumentException exception) {
            sendJson(exchange, 400, "{\"error\":\"" + jsonEscape(exception.getMessage()) + "\"}");
        }
    }

    private void handleHealth(HttpExchange exchange) throws IOException {
        sendText(exchange, 200, "OK");
    }

    private static boolean isMethod(HttpExchange exchange, String method) {
        return method.equalsIgnoreCase(exchange.getRequestMethod());
    }

    private static Map<String, String> parseForm(InputStream input, int maxBytes) throws IOException {
        byte[] body = input.readNBytes(maxBytes + 1);
        if (body.length > maxBytes) {
            throw new IllegalArgumentException("Form payload is too large.");
        }

        String encoded = new String(body, StandardCharsets.UTF_8);
        Map<String, String> fields = new LinkedHashMap<>();
        if (encoded.isBlank()) {
            return fields;
        }

        for (String pair : encoded.split("&")) {
            int separator = pair.indexOf('=');
            String key = separator >= 0 ? pair.substring(0, separator) : pair;
            String value = separator >= 0 ? pair.substring(separator + 1) : "";
            fields.put(urlDecode(key), urlDecode(value));
        }
        return fields;
    }

    private static String urlDecode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static int parseLinkType(String value) {
        try {
            int linkType = Integer.parseInt(value);
            if (linkType <= 0) {
                throw new IllegalArgumentException("Link type must be a positive integer.");
            }
            return linkType;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("Link type must be a number.", exception);
        }
    }

    private static String sanitizeFileName(String value) {
        String fileName = value == null ? "" : value.trim().replaceAll("[^A-Za-z0-9._-]", "_");
        if (fileName.isBlank()) {
            fileName = "packet.pcap";
        }
        if (!fileName.toLowerCase().endsWith(".pcap")) {
            fileName += ".pcap";
        }
        return fileName;
    }

    private static void sendHtml(HttpExchange exchange, int status, String html) throws IOException {
        byte[] response = html.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        exchange.sendResponseHeaders(status, response.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(response);
        }
    }

    private static void sendText(HttpExchange exchange, int status, String text) throws IOException {
        byte[] response = text.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(status, response.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(response);
        }
    }

    private static void sendJson(HttpExchange exchange, int status, String json) throws IOException {
        byte[] response = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, response.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(response);
        }
    }

    private static String jsonEscape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
