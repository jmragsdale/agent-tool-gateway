// npm install --no-save sharp, then node tools/build-readme-art.cjs
// Text stays in these SVG sources; PNG exports preserve the display typography.
const fs = require('node:fs/promises');
const path = require('node:path');
const sharp = require('sharp');
const out = path.resolve(__dirname, '../docs/assets/readme');
const esc = s => s.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
const face = "'DIN Alternate', 'Arial Narrow', Arial, sans-serif";
const text = (x,y,size,value,fill,font=face,weight=400,extra='') => `<text x="${x}" y="${y}" fill="${fill}" font-family="${font}" font-size="${size}" font-weight="${weight}" ${extra}>${esc(value)}</text>`;
const svg = (w,h,label,body) => `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img" aria-label="${esc(label)}"><title>${esc(label)}</title>${body}</svg>`;
async function save(name,source) {
  await fs.writeFile(path.join(out,name+'.svg'),source);
  await sharp(Buffer.from(source)).png().toFile(path.join(out,name+'.png'));
}
async function main() {
  await fs.mkdir(out,{recursive:true});
  const art = require('../docs/assets/readme/artwork.json');
  const navy='#101f2a', white='#f1f4ee', muted='#b7c8ca', teal='#72ddbd';
  let h=`<rect width="1440" height="500" rx="20" fill="${navy}"/><path d="M64 61H1376" stroke="#33454e"/><path d="M64 61H188" stroke="${teal}" stroke-width="4"/>`;
  h+=text(64,40,20,'J / R',white,face,700);
  h+=text(1376,40,16,'SECURITY ENGINEERING  /  REFERENCE CODE',muted,'Arial, sans-serif',400,'text-anchor="end" letter-spacing="2"');
  h+=text(64,121,20,art.eyebrow,teal,'Arial, sans-serif',700,'letter-spacing="4"');
  h+=text(60,223,art.titleFontSize||88,art.title,white,face,700);
  h+=text(64,286,36,art.tagline,white);
  h+=text(64,334,25,art.description[0],muted,'Arial, sans-serif');
  h+=text(64,371,25,art.description[1],muted,'Arial, sans-serif');
  h+='<path d="M64 413H1376" stroke="#33454e"/>';
  h+=text(64,458,22,art.footerLeft,teal,face,700);
  h+=text(285,458,21,art.footerMiddle,white);
  h+=text(1376,458,20,art.footerRight,muted,face,400,'text-anchor="end" letter-spacing="1"');
  h+='<g transform="translate(1075 139)"><rect width="301" height="221" rx="12" fill="#172d37" stroke="#3e5c64"/><path d="M38 116H263" stroke="#50777b" stroke-width="2"/>';
  for (const [i,label] of art.diagram.entries()) {
    const x=46+i*105;
    h+=`<circle cx="${x}" cy="116" r="${i===1?25:16}" fill="${i===1?teal:navy}" stroke="${teal}" stroke-width="2"/>`;
    if(i===1) h+='<path d="M141 116l7 7 13-15" stroke="#101f2a" stroke-width="3" fill="none"/>';
    h+=text(x,176,14,label,muted,'Arial, sans-serif',400,'text-anchor="middle" letter-spacing="1"');
  }
  h+=text(25,38,15,'ARCHITECTURE IN CODE',teal,'Arial, sans-serif',400,'letter-spacing="1"')+'</g>';
  const label=art.title+'. '+art.summary;
  await save('header',svg(1440,500,label,h));
  let m=`<rect width="700" height="690" rx="20" fill="${navy}"/><path d="M40 67H660" stroke="#33454e"/><path d="M40 67H160" stroke="${teal}" stroke-width="4"/>`;
  m+=text(40,43,22,'J / R',white,face,700);
  m+=text(660,43,18,'SECURITY ENGINEERING',muted,face,400,'text-anchor="end" letter-spacing="1"');
  m+=text(40,125,23,art.eyebrow,teal,'Arial, sans-serif',700,'letter-spacing="2"');
  m+=text(37,225,art.mobileTitle[0].length>12?72:86,art.mobileTitle[0],white,face,700);
  m+=text(37,320,art.mobileTitle[1].length>12?72:86,art.mobileTitle[1],white,face,700);
  m+=text(40,389,34,art.mobileTagline[0],white);
  m+=text(40,435,34,art.mobileTagline[1],white);
  m+=text(40,500,26,art.mobileDescription[0],muted,'Arial, sans-serif');
  m+=text(40,540,26,art.mobileDescription[1],muted,'Arial, sans-serif');
  m+='<path d="M40 586H660" stroke="#33454e"/>';
  m+=text(40,638,27,art.footerLeft,teal,face,700);
  m+=text(660,638,26,'REFERENCE CODE',white,face,400,'text-anchor="end"');
  await save('header-mobile',svg(700,690,label,m));
  for (const theme of ['light','dark']) {
    const c=theme==='light'?{bg:'#f4f6f3',border:'#d7e0db',ink:'#142c35',sub:'#405962',accent:'#087c63',rule:'#d5dfd9'}:{bg:'#122630',border:'#334a55',ink:'#f0f4ee',sub:'#b4c6cb',accent:'#72ddbd',rule:'#334a55'};
    for(const [index,card] of art.cards.entries()) {
      const {slug:name,category,title,lines,footer:stack}=card;
      const num=String(index+1).padStart(2,'0');
      let b=`<rect x="1" y="1" width="698" height="318" rx="12" fill="${c.bg}" stroke="${c.border}" stroke-width="2"/>`;
      b+=text(34,47,18,category,c.accent,'Arial, sans-serif',700,'letter-spacing="2"');
      b+=text(666,47,21,num,c.sub,face,400,'text-anchor="end"');
      b+=text(34,112,40,title,c.ink,face,700);
      b+=text(34,166,25,lines[0],c.sub,'Arial, sans-serif');
      b+=text(34,203,25,lines[1],c.sub,'Arial, sans-serif');
      b+=`<path d="M34 244H666" stroke="${c.rule}"/>`;
      b+=text(34,286,18,stack,c.sub,face,400,'letter-spacing="1"');
      b+=text(664,287,30,'↗',c.accent,'Arial, sans-serif',400,'text-anchor="end"');
      await save(name+'-'+theme,svg(700,320,title+'. '+lines.join(' ')+' '+stack,b));
    }
  }
}
main().catch(e=>{console.error(e);process.exitCode=1;});
