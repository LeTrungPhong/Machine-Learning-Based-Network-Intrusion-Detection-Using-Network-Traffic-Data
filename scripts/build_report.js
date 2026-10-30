// Build report.docx from docs/report.md.
//
// Usage:  node scripts/build_report.js [input.md] [output.docx]
//
// Supports the Markdown subset documented at the top of docs/report.md:
// "% " title block, #/##/### headings, paragraphs, "- " bullets (2-space
// indent = level 2), "1. " numbered items, pipe tables, images
// ![caption](path), **bold**, *italic*, `code`. HTML comments are skipped.
// Paragraphs starting with "Bảng N." are styled as table captions.

const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType, Table, TableRow, TableCell,
  WidthType, BorderStyle, ShadingType, ImageRun, TableOfContents, Footer, PageNumber, LevelFormat,
  PageBreak,
} = require("docx");

const ROOT = path.resolve(__dirname, "..");
const SRC = path.resolve(process.argv[2] || path.join(ROOT, "docs", "report.md"));
const OUT = path.resolve(process.argv[3] || path.join(ROOT, "report.docx"));

const FONT = "Times New Roman";
const SIZE = 26;                 // half-points: 13 pt
const PAGE_W = 11906;            // A4 portrait, DXA
const MARGIN = { top: 1134, bottom: 1134, left: 1701, right: 1134 };  // 2 / 2 / 3 / 2 cm
const TEXT_W = PAGE_W - MARGIN.left - MARGIN.right;
const BORDER = { style: BorderStyle.SINGLE, size: 4, color: "808080" };

// ---------- inline formatting ----------
function runs(text, base = {}) {
  const out = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`|\*[^*\s][^*]*\*)/g;
  let last = 0;
  for (const m of text.matchAll(re)) {
    if (m.index > last) out.push(new TextRun({ text: text.slice(last, m.index), ...base }));
    const t = m[0];
    if (t.startsWith("**")) out.push(...runs(t.slice(2, -2), { ...base, bold: true }));
    else if (t.startsWith("`")) out.push(new TextRun({ text: t.slice(1, -1), font: "Consolas", size: 22, ...base }));
    else out.push(new TextRun({ text: t.slice(1, -1), italics: true, ...base }));
    last = m.index + t.length;
  }
  if (last < text.length) out.push(new TextRun({ text: text.slice(last), ...base }));
  return out;
}

// ---------- block builders ----------
function para(text) {
  if (/^Bảng \d+\./.test(text)) {
    return new Paragraph({ style: "Caption", keepNext: true, children: runs(text) });
  }
  return new Paragraph({ alignment: AlignmentType.JUSTIFIED, children: runs(text) });
}

function table(rows) {
  const cells = rows.map((r) => r.replace(/^\||\|$/g, "").split("|").map((c) => c.trim()));
  const header = cells[0];
  const body = cells.slice(2);  // skip the |---| line
  const n = header.length;
  // Each column first gets room for its longest word (no mid-word wraps), then the
  // remaining width is shared in proportion to the longest cell text.
  const rowsNoRule = cells.filter((_, k) => k !== 1);
  const plain = (t) => (t || "").replace(/[*`]/g, "");
  const CHAR = 115;  // DXA per character at 11 pt, roughly
  const minW = header.map((_, i) => CHAR * Math.max(4, ...rowsNoRule.map((r) => Math.max(...plain(r[i]).split(/\s+/).map((w) => w.length)))) + 200);
  const len = header.map((_, i) => Math.max(3, ...rowsNoRule.map((r) => plain(r[i]).length)));
  let widths = minW.slice();
  const spare = TEXT_W - widths.reduce((a, b) => a + b, 0);
  if (spare > 0) {
    const extra = len.map((l, i) => Math.max(0, l * CHAR - minW[i]));
    const tot = extra.reduce((a, b) => a + b, 0) || 1;
    widths = widths.map((w, i) => w + Math.floor((spare * extra[i]) / tot));
  } else {
    widths = widths.map((w) => Math.floor((w * TEXT_W) / (TEXT_W - spare)));
  }
  widths[n - 1] += TEXT_W - widths.reduce((a, b) => a + b, 0);

  const mk = (row, isHeader) => new TableRow({
    tableHeader: isHeader,
    cantSplit: true,
    children: header.map((_, i) => new TableCell({
      width: { size: widths[i], type: WidthType.DXA },
      borders: { top: BORDER, bottom: BORDER, left: BORDER, right: BORDER },
      shading: isHeader ? { fill: "D9E2F3", type: ShadingType.CLEAR, color: "auto" } : undefined,
      margins: { top: 40, bottom: 40, left: 90, right: 90 },
      children: [new Paragraph({
        spacing: { before: 0, after: 0, line: 260 },
        children: runs(row[i] || "", { size: 22, ...(isHeader ? { bold: true } : {}) }),
      })],
    })),
  });
  return new Table({
    width: { size: TEXT_W, type: WidthType.DXA },
    columnWidths: widths,
    rows: [mk(header, true), ...body.map((r) => mk(r, false))],
  });
}

function pngSize(buf) {
  return { w: buf.readUInt32BE(16), h: buf.readUInt32BE(20) };
}

function image(caption, rel) {
  const file = path.resolve(path.dirname(SRC), rel);
  if (!fs.existsSync(file)) throw new Error(`Image not found: ${file}`);
  const buf = fs.readFileSync(file);
  const { w, h } = pngSize(buf);
  const maxW = 600;               // px at 96 dpi, about 15.9 cm (text width)
  const maxH = 620;
  const s = Math.min(maxW / w, maxH / h, 1);
  return [
    new Paragraph({
      alignment: AlignmentType.CENTER, keepNext: true, spacing: { before: 120, after: 60 },
      children: [new ImageRun({ type: "png", data: buf, transformation: { width: Math.round(w * s), height: Math.round(h * s) },
        altText: { title: caption, description: caption, name: path.basename(file) } })],
    }),
    new Paragraph({ style: "Caption", alignment: AlignmentType.CENTER, children: runs(caption) }),
  ];
}

// ---------- parse ----------
function parse(md) {
  const lines = md.replace(/<!--[\s\S]*?-->/g, "").split(/\r?\n/);
  const title = [];
  const body = [];
  let i = 0;
  let numbered = 0;               // numbering instance per list, so each list restarts at 1
  let inNumbered = false;
  while (i < lines.length) {
    const line = lines[i];
    if (line.startsWith("% ")) { title.push(line.slice(2).trim()); i++; continue; }
    if (!line.trim()) { inNumbered = false; i++; continue; }

    const h = line.match(/^(#{1,3}) (.*)$/);
    if (h) {
      const level = [HeadingLevel.HEADING_1, HeadingLevel.HEADING_2, HeadingLevel.HEADING_3][h[1].length - 1];
      body.push(new Paragraph({ heading: level, children: runs(h[2]) }));
      i++; continue;
    }
    if (line.startsWith("|")) {
      const rows = [];
      while (i < lines.length && lines[i].startsWith("|")) rows.push(lines[i++]);
      body.push(table(rows));
      body.push(new Paragraph({ spacing: { after: 60 }, children: [] }));
      continue;
    }
    const img = line.match(/^!\[(.*)\]\((.*)\)$/);
    if (img) { body.push(...image(img[1], img[2])); i++; continue; }

    const b = line.match(/^( *)- (.*)$/);
    if (b) {
      body.push(new Paragraph({ numbering: { reference: "bullets", level: b[1].length >= 2 ? 1 : 0 },
        alignment: AlignmentType.JUSTIFIED, children: runs(b[2]) }));
      i++; continue;
    }
    const n = line.match(/^\d+\. (.*)$/);
    if (n) {
      if (!inNumbered) { numbered++; inNumbered = true; }
      body.push(new Paragraph({ numbering: { reference: "numbers", level: 0, instance: numbered },
        alignment: AlignmentType.JUSTIFIED, children: runs(n[1]) }));
      i++; continue;
    }
    // Paragraph: join consecutive plain lines.
    const parts = [line.trim()];
    i++;
    while (i < lines.length && lines[i].trim() && !/^(#|\||!\[|\s*- |\d+\. |% )/.test(lines[i])) parts.push(lines[i++].trim());
    body.push(para(parts.join(" ")));
  }
  return { title, body };
}

function titlePage(title) {
  const [main, sub, note] = title;
  const p = (text, opts) => new Paragraph({ alignment: AlignmentType.CENTER, ...opts, children: [new TextRun({ text, font: FONT, ...opts.run })] });
  return [
    p("BÁO CÁO NGHIÊN CỨU KHOA HỌC", { spacing: { before: 2400, after: 600 }, run: { size: 28, bold: true } }),
    p(main || "", { spacing: { after: 300 }, run: { size: 36, bold: true, color: "1F3864" } }),
    p(sub || "", { spacing: { after: 1800 }, run: { size: 26, italics: true } }),
    p(note || "", { spacing: { after: 200 }, run: { size: 24 } }),
    new Paragraph({ children: [new PageBreak()] }),
    new Paragraph({ style: "TOCHeading", children: [new TextRun("MỤC LỤC")] }),
    new TableOfContents("Mục lục", { hyperlink: true, headingStyleRange: "1-3" }),
    new Paragraph({ children: [new PageBreak()] }),
  ];
}

// ---------- document ----------
const { title, body } = parse(fs.readFileSync(SRC, "utf8"));

const heading = (id, name, size, before, after, extra = {}) => ({
  id, name, basedOn: "Normal", next: "Normal", quickFormat: true,
  run: { font: FONT, size, bold: true, color: "1F3864", ...extra.run },
  paragraph: { spacing: { before, after, line: 300 }, keepNext: true, outlineLevel: extra.outline },
});

const doc = new Document({
  creator: "ATTT_Project",
  title: title[0] || "Report",
  features: { updateFields: true },
  styles: {
    default: { document: { run: { font: FONT, size: SIZE } } },
    paragraphStyles: [
      { id: "Normal", name: "Normal", run: { font: FONT, size: SIZE },
        paragraph: { spacing: { before: 0, after: 120, line: 312 } } },
      heading("Heading1", "Heading 1", 30, 240, 180, { outline: 0 }),
      heading("Heading2", "Heading 2", 27, 200, 120, { outline: 1 }),
      heading("Heading3", "Heading 3", 26, 160, 100, { outline: 2, run: { italics: true } }),
      { id: "Caption", name: "Caption", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: 22, italics: true, color: "404040" },
        paragraph: { spacing: { before: 60, after: 120 } } },
      { id: "TOCHeading", name: "TOC Heading", basedOn: "Normal", next: "Normal",
        run: { font: FONT, size: 30, bold: true, color: "1F3864" },
        paragraph: { alignment: AlignmentType.CENTER, spacing: { after: 240 } } },
    ],
  },
  numbering: {
    config: [
      { reference: "bullets", levels: [
        { level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 567, hanging: 283 } } } },
        { level: 1, format: LevelFormat.BULLET, text: "–", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 1134, hanging: 283 } } } },
      ] },
      { reference: "numbers", levels: [
        { level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 567, hanging: 340 } } } },
      ] },
    ],
  },
  sections: [{
    properties: { page: { size: { width: PAGE_W, height: 16838 }, margin: MARGIN } },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER,
      children: [new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 22 })] })] }) },
    children: [...titlePage(title), ...body],
  }],
});

Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync(OUT, buf);
  console.log(`Wrote ${OUT} (${(buf.length / 1024).toFixed(0)} KB, ${body.length} blocks)`);
});
