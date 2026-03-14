// agent/duckduckgo/core/html-parser.js
// HTML → text/markdown parser for DuckDuckGo HTML-mode responses

class HtmlParser {
    /**
     * Extract search results from DuckDuckGo HTML response.
     *
     * @param {string} html — Raw HTML from html.duckduckgo.com
     * @returns {{ found: boolean, text: string }}
     */
    static extractSearchResults(html) {
        if (!html || typeof html !== 'string') {
            return { found: false, text: '' };
        }

        // Strip scripts, styles
        var clean = html;
        clean = HtmlParser.removeElements(clean, 'script');
        clean = HtmlParser.removeElements(clean, 'style');
        clean = HtmlParser.removeElements(clean, 'noscript');
        clean = HtmlParser.removeElements(clean, 'svg');

        var results = [];

        // ── Extract Zero-Click (instant answer) ──
        var zeroClick = HtmlParser.extractByClass(clean, 'zci__result')
            || HtmlParser.extractByClass(clean, 'zci__main')
            || HtmlParser.extractByAttribute(clean, 'id', 'zero_click_wrapper');
        if (zeroClick) {
            var zcText = HtmlParser.htmlToMarkdown(zeroClick);
            if (zcText && zcText.length > 20) {
                results.push('## Answer\n' + zcText);
            }
        }

        // ── Extract organic results ──
        var pos = 0;
        var count = 0;
        while (count < 8) {
            var nextIdx = clean.indexOf('class="result ', pos);
            if (nextIdx === -1) nextIdx = clean.indexOf('class="result"', pos);
            if (nextIdx === -1) break;

            var tagStart = clean.lastIndexOf('<', nextIdx);
            if (tagStart === -1) { pos = nextIdx + 1; continue; }

            var tagNameEnd = clean.indexOf(' ', tagStart + 1);
            if (tagNameEnd === -1) { pos = nextIdx + 1; continue; }
            var tagName = clean.substring(tagStart + 1, tagNameEnd);

            var block = HtmlParser.extractTagContent(clean, tagStart, tagName);
            if (!block) { pos = nextIdx + 1; continue; }

            // Title
            var title = '';
            var titleMatch = block.match(/<a[^>]*class="[^"]*result__a[^"]*"[^>]*>(.*?)<\/a>/i);
            if (titleMatch) title = HtmlParser.stripTags(titleMatch[1]);

            // URL
            var href = '';
            var hrefMatch = block.match(/<a[^>]*class="[^"]*result__url[^"]*"[^>]*href="([^"]*)"/i);
            if (!hrefMatch) hrefMatch = block.match(/<a[^>]*class="[^"]*result__a[^"]*"[^>]*href="([^"]*)"/i);
            if (hrefMatch) href = hrefMatch[1].replace(/&amp;/g, '&');

            // Snippet
            var snippet = '';
            var snippetBlock = HtmlParser.extractByClass(block, 'result__snippet');
            if (snippetBlock) snippet = HtmlParser.htmlToMarkdown(snippetBlock);

            if (title || snippet) {
                var entry = '';
                if (title && href) {
                    entry += '### [' + title + '](' + href + ')\n';
                } else if (title) {
                    entry += '### ' + title + '\n';
                }
                if (snippet) entry += snippet + '\n';
                results.push(entry);
                count++;
            }

            pos = tagStart + (block ? block.length : 1);
        }

        if (results.length > 0) {
            return { found: true, text: results.join('\n') };
        }

        // Fallback: convert whole body
        var bodyText = HtmlParser.htmlToMarkdown(clean);
        if (bodyText && bodyText.length > 50) {
            return { found: true, text: bodyText.substring(0, 3000) };
        }

        return { found: false, text: '' };
    }

    // ── HTML utilities ──────────────────────────────────────────────────

    static extractByAttribute(html, attr, value) {
        var pattern = attr + '="' + value + '"';
        var idx = html.indexOf(pattern);
        if (idx === -1) return null;
        var tagStart = html.lastIndexOf('<', idx);
        if (tagStart === -1) return null;
        var tagNameEnd = html.indexOf(' ', tagStart + 1);
        if (tagNameEnd === -1 || tagNameEnd > idx) tagNameEnd = html.indexOf('>', tagStart + 1);
        var tagName = html.substring(tagStart + 1, tagNameEnd);
        return HtmlParser.extractTagContent(html, tagStart, tagName);
    }

    static extractByClass(html, className) {
        var patterns = [
            'class="' + className + '"',
            'class="' + className + ' ',
            ' ' + className + '"',
            ' ' + className + ' '
        ];
        for (var i = 0; i < patterns.length; i++) {
            var idx = html.indexOf(patterns[i]);
            if (idx !== -1) {
                var tagStart = html.lastIndexOf('<', idx);
                if (tagStart === -1) continue;
                var tagNameEnd = html.indexOf(' ', tagStart + 1);
                if (tagNameEnd === -1) continue;
                var tagName = html.substring(tagStart + 1, tagNameEnd);
                var result = HtmlParser.extractTagContent(html, tagStart, tagName);
                if (result) return result;
            }
        }
        return null;
    }

    static extractTagContent(html, startPos, tagName) {
        var depth = 0;
        var pos = startPos;
        var openTag = '<' + tagName;
        var closeTag = '</' + tagName;
        while (pos < html.length) {
            var nextOpen = html.indexOf(openTag, pos + 1);
            var nextClose = html.indexOf(closeTag, pos + 1);
            if (pos === startPos) { depth = 1; pos = html.indexOf('>', startPos) + 1; continue; }
            if (nextClose === -1) return null;
            if (nextOpen !== -1 && nextOpen < nextClose) {
                var c = html.charAt(nextOpen + openTag.length);
                if (c === ' ' || c === '>' || c === '/') depth++;
                pos = nextOpen + 1;
            } else {
                depth--;
                if (depth === 0) return html.substring(startPos, html.indexOf('>', nextClose) + 1);
                pos = nextClose + 1;
            }
            if (pos - startPos > 500000) return null;
        }
        return null;
    }

    static removeElements(html, tagName) {
        var result = html;
        var openTag = '<' + tagName;
        var closeTag = '</' + tagName + '>';
        while (true) {
            var start = result.toLowerCase().indexOf(openTag.toLowerCase());
            if (start === -1) break;
            var end = result.toLowerCase().indexOf(closeTag.toLowerCase(), start);
            if (end === -1) {
                end = result.indexOf('>', start);
                if (end === -1) break;
                result = result.substring(0, start) + result.substring(end + 1);
            } else {
                result = result.substring(0, start) + result.substring(end + closeTag.length);
            }
        }
        return result;
    }

    static stripTags(html) {
        return (html || '').replace(/<[^>]+>/g, '')
            .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
            .replace(/&quot;/g, '"').replace(/&#39;/g, "'").trim();
    }

    static htmlToMarkdown(html) {
        var t = html;
        t = t.replace(/<h[1-4][^>]*>(.*?)<\/h[1-4]>/gi, '\n**$1**\n');
        t = t.replace(/<(strong|b)[^>]*>(.*?)<\/(strong|b)>/gi, '**$2**');
        t = t.replace(/<(em|i)[^>]*>(.*?)<\/(em|i)>/gi, '*$2*');
        t = t.replace(/<a[^>]*href="([^"]*)"[^>]*>(.*?)<\/a>/gi, '[$2]($1)');
        t = t.replace(/<br\s*\/?>/gi, '\n');
        t = t.replace(/<li[^>]*>(.*?)<\/li>/gi, '- $1\n');
        t = t.replace(/<p[^>]*>/gi, '\n');
        t = t.replace(/<\/p>/gi, '\n');
        t = t.replace(/<div[^>]*>/gi, '\n');
        t = t.replace(/<\/div>/gi, '');
        t = t.replace(/<[^>]+>/g, '');
        t = t.replace(/&amp;/g, '&');
        t = t.replace(/&lt;/g, '<');
        t = t.replace(/&gt;/g, '>');
        t = t.replace(/&quot;/g, '"');
        t = t.replace(/&#39;/g, "'");
        t = t.replace(/&nbsp;/g, ' ');
        t = t.replace(/&#x27;/g, "'");
        t = t.replace(/&#x2F;/g, '/');
        t = t.replace(/\n{3,}/g, '\n\n');
        t = t.replace(/[ \t]+/g, ' ');
        t = t.replace(/\n /g, '\n');
        return t.trim();
    }
}

module.exports = HtmlParser;
