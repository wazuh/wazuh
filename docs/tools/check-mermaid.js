// Parse mermaid diagrams with the exact mermaid build the book ships (docs/mermaid.min.js).
//
// Usage: node check-mermaid.js <mermaid.min.js>  < diagrams.json
// stdin is a JSON array of diagram sources; stdout is a JSON array of the same length holding
// null for a diagram that parses and the first line of the parse error otherwise.
// Needs jsdom, pinned by docs/tools/package-lock.json; check-docs.py installs it outside docs/
// and passes it through NODE_PATH.

const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const bundle = fs.readFileSync(path.resolve(process.argv[2]), 'utf8');
const diagrams = JSON.parse(fs.readFileSync(0, 'utf8'));

const dom = new JSDOM('<!doctype html><body></body>', { runScripts: 'dangerously', pretendToBeVisual: true });
const script = dom.window.document.createElement('script');
script.textContent = bundle;
dom.window.document.body.appendChild(script);
const mermaid = dom.window.mermaid;
mermaid.initialize({ startOnLoad: false });

(async () => {
    const results = [];
    for (const source of diagrams) {
        try {
            await mermaid.parse(source);
            results.push(null);
        } catch (e) {
            results.push(String((e && e.message) || e).split('\n').filter(Boolean).slice(0, 2).join(' '));
        }
    }
    process.stdout.write(JSON.stringify(results));
})();
