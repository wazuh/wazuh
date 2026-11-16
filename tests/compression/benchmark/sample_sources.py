#!/usr/bin/env python3
"""Read selected closed gzip logs and stream stratified samples as a tar archive.
The source manifest is private; stdout contains real log content.
"""
import os,sys,json,gzip,hashlib,tarfile,io,time
files=json.load(open(sys.argv[1]))
manifest=[]
with tarfile.open(fileobj=sys.stdout.buffer,mode='w|') as tar:
 for index,item in enumerate(files):
  before=os.stat(item['path'])
  if before.st_size!=item['size'] or before.st_mtime!=item['mtime']:raise RuntimeError('Source changed')
  hint=item['raw_size_hint']; window=32*1024*1024
  ranges=[(0,hint)] if item['family']=='alerts' else [(0,window),((hint-window)//2,(hint+window)//2),(hint-window,hint)]
  buffers=[bytearray() for _ in ranges];position=0;digest=hashlib.sha256();lines=0
  with gzip.open(item['path'],'rb') as source:
   while True:
    block=source.read(1024*1024)
    if not block:break
    digest.update(block);lines+=block.count(b'\n');end=position+len(block)
    for buf,(start,stop) in zip(buffers,ranges):
     left=max(start,position);right=min(stop,end)
     if left<right:buf.extend(block[left-position:right-position])
    position=end
  if position!=hint:raise RuntimeError('gzip size hint differed from true size; recollect with correct size')
  pieces=[];segments=[]
  for buf,(start,stop) in zip(buffers,ranges):
   left=0 if start==0 else buf.find(b'\n')+1
   right=len(buf) if stop==position else buf.rfind(b'\n')+1
   if left>=right:raise RuntimeError('No complete records in sample window')
   data=bytes(buf[left:right]);pieces.append(data);segments.append(dict(offset=start+left,length=len(data)))
  sample=b''.join(pieces)
  day=index//3+1;kind='alerts-log' if item['name'].endswith('-log.gz') else ('alerts-json' if item['family']=='alerts' else 'archives-json')
  name=f'D{day:02d}-{kind}.bin'
  info=tarfile.TarInfo(name);info.size=len(sample);info.mode=0o600;tar.addfile(info,io.BytesIO(sample))
  after=os.stat(item['path'])
  if (before.st_size,before.st_mtime)!=(after.st_size,after.st_mtime):raise RuntimeError('Source changed during read')
  manifest.append(dict(id=name[:-4],filename=name,kind=kind,day=day,source=item['path'],source_bytes=position,source_sha256=digest.hexdigest(),sample_bytes=len(sample),sample_sha256=hashlib.sha256(sample).hexdigest(),sample_lines=sample.count(b'\n'),segments=segments))
  print('Collected',name,len(sample),'bytes from',position,'source bytes',file=sys.stderr,flush=True)
 data=json.dumps(manifest,indent=2).encode();info=tarfile.TarInfo('private-manifest.json');info.size=len(data);info.mode=0o600;tar.addfile(info,io.BytesIO(data))
