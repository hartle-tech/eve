#!/usr/bin/env python3
"""Render docs/*.md into the site's /docs, at image build time.

The README is a landing page; the depth lives in docs/*.md; and this turns
those same files into pages so nobody has to read Markdown in a repository to
find out what a command does or which paths eve refuses to touch. One source.
The site cannot drift from the thing it describes because it is built from it.

Stdlib only — same reason eve's own crates pull almost nothing in.

    python3 web/render-docs.py docs web/_docs
"""

import html
import os
import re
import sys

# Which files become pages, in nav order, with the label and blurb the index
# card carries. A file not listed here is not published.
PAGES = [
    ("INSTALL.md", "Install",
     "The app, the CLI, the privileged extras, and Full Disk Access."),
    ("SAFETY.md", "Safety",
     "The five gates every deletion passes, and the risk tiers."),
]

REPO = "https://github.com/hartle-tech/eve"

# The landing page's palette, narrowed to what a prose page needs. Kept here
# rather than imported from eve.css because these pages are generated into
# /docs and should not break if the landing stylesheet is restructured.
CSS = """
:root{--bg:#05080a;--ink:#f2f5f5;--dim:rgba(242,245,245,.64);
--faint:rgba(242,245,245,.42);--line:rgba(242,245,245,.11);
--card:rgba(242,245,245,.04);--card-edge:rgba(242,245,245,.085);
--teal:#2fc4b8;--mint:#4fe7c8;--amber:#ffb100;--coral:#ff6b62;--max:1180px}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);
font:400 17px/1.65 -apple-system,BlinkMacSystemFont,"SF Pro Text","Inter","Helvetica Neue",Arial,sans-serif;
-webkit-font-smoothing:antialiased}
a{color:var(--mint);text-decoration:none}
a:hover{text-decoration:underline}
img{max-width:100%;height:auto}
:focus-visible{outline:2px solid var(--mint);outline-offset:3px;border-radius:4px}

.bar{position:sticky;top:0;z-index:50;display:flex;align-items:center;
gap:16px;padding:13px max(22px,calc((100vw - var(--max))/2));
background:rgba(5,8,10,.72);backdrop-filter:saturate(180%) blur(18px);
-webkit-backdrop-filter:saturate(180%) blur(18px);
border-bottom:1px solid var(--line)}
.bar .home{display:flex;align-items:center;gap:9px;color:var(--ink);font-weight:600}
.bar .home:hover{text-decoration:none}
.bar .home img{width:21px;height:21px;display:block}
.bar nav{margin-left:auto;display:flex;gap:18px;flex-wrap:wrap}
.bar nav a{color:var(--dim);font-size:14.5px}
.bar nav a:hover{color:var(--ink);text-decoration:none}

.wrap{max-width:var(--max);margin:0 auto;padding:0 22px;
display:grid;grid-template-columns:212px minmax(0,1fr);gap:52px}
@media(max-width:860px){.wrap{grid-template-columns:1fr;gap:0}
aside{position:static!important;padding:22px 0 0!important;max-height:none!important}}

aside{position:sticky;top:74px;align-self:start;padding:44px 0;
max-height:calc(100vh - 74px);overflow:auto}
aside h2{font-size:11px;letter-spacing:.14em;text-transform:uppercase;
color:var(--faint);margin:0 0 12px}
aside ul{list-style:none;margin:0 0 26px;padding:0}
aside li{margin:0 0 3px}
aside a{display:block;padding:5px 11px;margin-left:-11px;border-radius:8px;
color:var(--dim);font-size:15px}
aside a:hover{background:var(--card);color:var(--ink);text-decoration:none}
aside a.on{background:var(--card);color:var(--ink);
box-shadow:inset 2px 0 0 var(--teal)}
aside .sub a{font-size:14px;padding-left:22px;color:var(--faint)}

main{padding:44px 0 96px;min-width:0}
main>h1{font-size:clamp(30px,4.4vw,44px);line-height:1.1;letter-spacing:-.022em;
margin:0 0 28px;background:linear-gradient(104deg,var(--mint) 8%,var(--teal) 74%);
-webkit-background-clip:text;background-clip:text;color:transparent}
main h2{font-size:25px;letter-spacing:-.012em;margin:52px 0 14px;
padding-top:18px;border-top:1px solid var(--line)}
main h3{font-size:19px;margin:34px 0 10px}
main h4{font-size:17px;margin:26px 0 8px;color:var(--dim)}
main p{margin:0 0 16px;color:var(--dim);max-width:70ch}
main strong{color:var(--ink)}
main em{color:var(--ink);font-style:italic}
main li{color:var(--dim);margin:0 0 7px;max-width:70ch}
main ul,main ol{padding-left:22px}

code{font:500 13.5px/1.5 ui-monospace,SFMono-Regular,"SF Mono",Menlo,monospace;
background:var(--card);border:1px solid var(--card-edge);border-radius:6px;
padding:.12em .4em;color:var(--mint)}
pre{background:#04090c;border:1px solid var(--card-edge);border-radius:13px;
padding:17px 19px;overflow-x:auto;margin:0 0 20px}
pre code{background:0;border:0;padding:0;color:#cfe9e6;font-size:13.5px;line-height:1.62}

table{border-collapse:collapse;width:100%;margin:0 0 22px;font-size:15px;
display:block;overflow-x:auto}
th,td{text-align:left;padding:9px 14px;border-bottom:1px solid var(--line);
vertical-align:top;color:var(--dim)}
th{color:var(--faint);font-size:11.5px;letter-spacing:.1em;text-transform:uppercase;
font-weight:600;white-space:nowrap}
td strong{color:var(--ink)}

blockquote{margin:0 0 20px;padding:14px 19px;border-left:3px solid var(--amber);
background:var(--card);border-radius:0 11px 11px 0}
blockquote p{margin:0;color:var(--ink)}
hr{border:0;border-top:1px solid var(--line);margin:36px 0}

.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(248px,1fr));
gap:15px;margin:0 0 30px;padding:0;list-style:none}
.cards a{display:block;height:100%;padding:19px 21px;border-radius:15px;
background:var(--card);border:1px solid var(--card-edge);color:var(--ink)}
.cards a:hover{border-color:var(--teal);text-decoration:none;
background:rgba(47,196,184,.06)}
.cards b{display:block;font-size:17px;margin:0 0 5px}
.cards span{color:var(--dim);font-size:14.5px;line-height:1.5}

footer{border-top:1px solid var(--line);padding:26px 0 0;margin-top:60px;
color:var(--faint);font-size:14px}
footer a{color:var(--dim)}
"""


def slug(text):
    """GitHub's anchor rule, near enough: lowercase, strip punctuation,
    spaces to hyphens. Keeps in-page links working across both renderings."""
    s = re.sub(r"<[^>]+>", "", text).lower()
    s = re.sub(r"[^\w\s-]", "", s, flags=re.UNICODE)
    return re.sub(r"[\s-]+", "-", s).strip("-")


def inline(text):
    """Inline markdown. Code spans are pulled out first so nothing formats
    inside them — otherwise `--no-color` grows an <em>."""
    spans = []

    def stash(m):
        spans.append(m.group(1))
        return "\x00%d\x00" % (len(spans) - 1)

    text = re.sub(r"`([^`]+)`", stash, text)
    text = html.escape(text, quote=False)
    text = re.sub(r"!\[([^\]]*)\]\(([^)]+)\)",
                  lambda m: '<img src="%s" alt="%s">' % (m.group(2), m.group(1)), text)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", link, text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<![\w*])\*([^*\n]+)\*(?![\w*])", r"<em>\1</em>", text)
    text = re.sub(r"\x00(\d+)\x00",
                  lambda m: "<code>%s</code>" % html.escape(spans[int(m.group(1))]), text)
    return text


def link(m):
    label, href = m.group(1), m.group(2)
    # A sibling .md becomes its rendered page; ../ escapes docs/ entirely and
    # can only sensibly point at the repository.
    if href.startswith("../"):
        href = REPO + "/blob/main/" + href[3:]
    elif href.endswith(".md") or ".md#" in href:
        name, _, frag = href.partition("#")
        href = name[:-3].lower() + (".html#" + frag if frag else ".html")
    return '<a href="%s">%s</a>' % (html.escape(href, quote=True), label)


def render(md):
    """Markdown → (html, [(level, text, anchor)])."""
    out, toc, lines, i = [], [], md.split("\n"), 0
    while i < len(lines):
        ln = lines[i]

        if ln.startswith("```"):
            body, i = [], i + 1
            while i < len(lines) and not lines[i].startswith("```"):
                body.append(lines[i])
                i += 1
            out.append("<pre><code>%s</code></pre>"
                       % html.escape("\n".join(body), quote=False))
            i += 1
            continue

        m = re.match(r"(#{1,4})\s+(.*)", ln)
        if m:
            lvl, text = len(m.group(1)), m.group(2).strip()
            a = slug(text)
            if lvl in (2, 3):
                toc.append((lvl, text, a))
            out.append('<h%d id="%s">%s</h%d>' % (lvl, a, inline(text), lvl))
            i += 1
            continue

        if ln.startswith("|") and i + 1 < len(lines) and re.match(r"^\|[\s:|-]+\|$", lines[i + 1]):
            head = [c.strip() for c in ln.strip("|").split("|")]
            i += 2
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append([c.strip() for c in lines[i].strip("|").split("|")])
                i += 1
            th = "".join("<th>%s</th>" % inline(c) for c in head)
            tb = "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % inline(c) for c in r)
                         for r in rows)
            out.append("<table><thead><tr>%s</tr></thead><tbody>%s</tbody></table>" % (th, tb))
            continue

        if re.match(r"^\s*[-*]\s+|^\s*\d+\.\s+", ln):
            ordered = bool(re.match(r"^\s*\d+\.", ln))
            items = []
            while i < len(lines) and (re.match(r"^\s*[-*]\s+|^\s*\d+\.\s+", lines[i])
                                      or (lines[i].startswith("  ") and lines[i].strip() and items)):
                if re.match(r"^\s*[-*]\s+|^\s*\d+\.\s+", lines[i]):
                    items.append(re.sub(r"^\s*(?:[-*]|\d+\.)\s+", "", lines[i]))
                else:                       # a wrapped continuation line
                    items[-1] += " " + lines[i].strip()
                i += 1
            tag = "ol" if ordered else "ul"
            out.append("<%s>%s</%s>" % (tag, "".join("<li>%s</li>" % inline(x)
                                                    for x in items), tag))
            continue

        if ln.startswith(">"):
            body = []
            while i < len(lines) and lines[i].startswith(">"):
                body.append(lines[i].lstrip(">").strip())
                i += 1
            out.append("<blockquote><p>%s</p></blockquote>" % inline(" ".join(body)))
            continue

        if ln.strip() in ("---", "***", "___"):
            out.append("<hr>")
            i += 1
            continue

        if not ln.strip():
            i += 1
            continue

        para = []
        while i < len(lines) and lines[i].strip() and not re.match(
                r"^(#{1,4}\s|```|\||>|\s*[-*]\s+|\s*\d+\.\s+|---$)", lines[i]):
            para.append(lines[i].strip())
            i += 1
        out.append("<p>%s</p>" % inline(" ".join(para)))

    return "\n".join(out), toc


def shell(title, nav, aside, body, blurb=""):
    return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s — eve docs</title>
<meta name="description" content="%s">
<link rel="icon" href="/favicon.ico" sizes="48x48">
<link rel="icon" href="/mark.svg" type="image/svg+xml" sizes="any">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<!-- A real stylesheet, not a <style> block: the site's CSP is
     `style-src 'self'` with no 'unsafe-inline', and an inline block is
     dropped silently — the page renders, entirely unstyled. -->
<link rel="stylesheet" href="/docs/docs.css">
</head>
<body>
<header class="bar">
  <a class="home" href="/">
    <img src="/mark.svg" alt="" width="21" height="21">
    eve
  </a>
  <nav>%s</nav>
</header>
<div class="wrap">
<aside>%s</aside>
<main>
%s
<footer>Apache-2.0 · © HARTLE.TECH ·
<a href="mailto:contact@hartle.tech">contact@hartle.tech</a> ·
<a href="%s">GitHub</a> ·
<a href="/#support">Support this work</a></footer>
</main>
</div>
</body>
</html>
""" % (html.escape(title), html.escape(blurb or title), nav, aside, body, REPO)


def main(src, dst):
    os.makedirs(dst, exist_ok=True)
    with open(os.path.join(dst, "docs.css"), "w", encoding="utf-8") as fh:
        fh.write(CSS.strip() + "\n")

    nav = ('<a href="/docs/">Docs</a><a href="/#reach">Features</a>'
           '<a href="/#gates">Safety</a>'
           '<a href="%s">GitHub</a>'
           '<a href="/#support">Support</a>' % REPO)

    def sidebar(current, toc=()):
        """The page list, plus this page's own H2s under it."""
        items = "".join(
            '<li><a class="%s" href="%s.html">%s</a></li>'
            % ("on" if f == current else "", f[:-3].lower(), t)
            for f, t, _ in PAGES)
        out = "<h2>Docs</h2><ul>%s</ul>" % items
        heads = [(t, a) for lvl, t, a in toc if lvl == 2]
        if heads:
            out += '<h2>On this page</h2><ul class="sub">%s</ul>' % "".join(
                '<li><a href="#%s">%s</a></li>' % (a, html.escape(t)) for t, a in heads)
        return out

    written = []
    for fname, title, blurb in PAGES:
        path = os.path.join(src, fname)
        if not os.path.exists(path):
            print("  skip (absent) %s" % fname)
            continue
        with open(path, encoding="utf-8") as fh:
            body, toc = render(fh.read())
        out = os.path.join(dst, fname[:-3].lower() + ".html")
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(shell(title, nav, sidebar(fname, toc), body, blurb))
        written.append((fname, title, blurb))
        print("  %-28s -> %s" % (fname, os.path.basename(out)))

    if not written:
        # An empty /docs is a link in the header that goes nowhere. Better to
        # fail the image build than to ship one.
        print("error: no pages were rendered from %r" % src, file=sys.stderr)
        return 1

    cards = "".join(
        '<li><a href="%s.html"><b>%s</b><span>%s</span></a></li>'
        % (f[:-3].lower(), html.escape(t), html.escape(b)) for f, t, b in written)
    index = shell(
        "Docs", nav, sidebar(None),
        "<h1>eve docs</h1>"
        "<p>Everything the README deliberately does not say: how to install it, "
        "and the rules every deletion passes through. The same files live in "
        '<a href="%s/tree/main/docs"><code>docs/</code></a> in the repository, '
        "and these pages are built from them.</p>"
        '<ul class="cards">%s</ul>' % (REPO, cards),
        "How to install eve, and the five gates every deletion passes.")
    with open(os.path.join(dst, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(index)
    print("  %-28s -> index.html, docs.css" % "(index)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "docs",
                  sys.argv[2] if len(sys.argv) > 2 else "web/_docs"))
