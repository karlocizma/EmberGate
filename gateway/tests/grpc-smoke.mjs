// Native HTTP/2 framing, duplex streaming, metadata, trailers, and protocol isolation.
import assert from 'node:assert/strict';
import http2 from 'node:http2';
import http from 'node:http';
import net from 'node:net';
import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {spawn} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {once} from 'node:events';
const listen=async server=>{server.listen(0,'127.0.0.1');await once(server,'listening');return server.address().port;};
const free=async()=>{const s=net.createServer();const p=await listen(s);await new Promise(r=>s.close(r));return p;};
const directory=await mkdtemp(`${tmpdir()}/embergate-grpc-`);
const backend=http2.createServer();
backend.on('stream',(stream,headers)=>{
  stream.respond({':status':200,'content-type':'application/grpc','x-echo-metadata':headers['x-client-metadata']||'none'},{waitForTrailers:true});
  stream.on('data',chunk=>stream.write(chunk));
  stream.on('end',()=>stream.end());
  stream.on('wantTrailers',()=>stream.sendTrailers({'grpc-status':headers[':path'].endsWith('/Error')?'7':'0','grpc-message':'fixture','grpc-status-details-bin':'AQID'}));
  stream.on('error',()=>{});
});
let process,client,tlsClient,tlsBackend;let logs='';
const watchdog=setTimeout(()=>{console.error(logs);globalThis.process.exit(1);},30000).unref();
try {
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','2','-keyout',directory+'/key.pem','-out',directory+'/cert.pem','-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1,DNS:127.0.0.1,DNS:localhost,DNS:auto.test,DNS:http2.test,DNS:http1.test'],{stdio:'ignore'});
  const key=readFileSync(directory+'/key.pem'),cert=readFileSync(directory+'/cert.pem');
  tlsBackend=http2.createSecureServer({key,cert,allowHTTP1:true});
  tlsBackend.on('request',(request,response)=>{
    if(request.httpVersionMajor===1){response.end('ordinary HTTP');return;}
    response.writeHead(200,{'content-type':'application/grpc'});
    request.on('data',chunk=>response.write(chunk));
    request.on('end',()=>{response.addTrailers({'grpc-status':'0'});response.end();});
  });
  const tlsOrigin=await listen(tlsBackend);
  const origin=await listen(backend),admin=await free(),proxy=await free(),https=await free();
  const env=Object.fromEntries(Object.entries(globalThis.process.env).filter(([key])=>!key.startsWith('GATEWAY_')));
  process=spawn('target/debug/embergate',[],{env:{...env,SSL_CERT_FILE:directory+'/cert.pem',GATEWAY_HTTPS_ADDR:`127.0.0.1:${https}`,GATEWAY_DATA_DIR:directory,GATEWAY_ADMIN_ADDR:`127.0.0.1:${admin}`,GATEWAY_PROXY_ADDR:`127.0.0.1:${proxy}`,GATEWAY_ADMIN_PASSWORD:'grpc-test-password'}});
  process.stderr.on('data',chunk=>logs+=chunk);
  const base=`http://127.0.0.1:${admin}`;
  for(let i=0;;i++){try {await fetch(base+'/api/config');break;}catch(error){if(i===99)throw error;await new Promise(r=>setTimeout(r,100));}}
  const login=await fetch(base+'/api/login',{method:'POST',headers:{'Content-Type':'application/json','X-Gateway-Request':'1'},body:JSON.stringify({username:'admin',password:'grpc-test-password'})});
  assert.equal(login.status,200);
  const headers={'Content-Type':'application/json','X-Gateway-Request':'1',Cookie:login.headers.get('set-cookie').split(';')[0]};
  const routes=['auto','http2','http1'].map((protocol,i)=>({id:crypto.randomUUID(),name:protocol,host:`${protocol}.test`,path_prefix:'/',upstream:`http://127.0.0.1:${origin}`,enabled:true,preserve_host:true,upstream_protocol:protocol}));
  const saved=await fetch(base+'/api/config',{method:'PUT',headers,body:JSON.stringify({version:0,routes})});assert.equal(saved.status,200,await saved.text());
  const invalid=structuredClone(routes);invalid[1].health_check={path:'/',interval_seconds:10,timeout_seconds:3,failure_threshold:2,recovery_threshold:1};
  assert.equal((await fetch(base+'/api/config',{method:'PUT',headers,body:JSON.stringify({version:1,routes:invalid})})).status,422);
  const uploaded=await fetch(base+'/api/certificates',{method:'POST',headers,body:JSON.stringify({name:'gRPC fixture',certificate_pem:cert.toString(),private_key_pem:key.toString()})});assert.equal(uploaded.status,200,await uploaded.text());
  client=http2.connect(`http://127.0.0.1:${proxy}`);
  const frame=Buffer.from([0,0,0,0,3,97,98,99]);
  for(const protocol of ['auto','http2'])for(const method of ['Echo','Error']) {
    const stream=client.request({':authority':`${protocol}.test`,':method':'POST',':path':`/fixture.Service/${method}`,'content-type':'application/grpc','te':'trailers','x-client-metadata':'preserved'});
    const response=once(stream,'response');const first=once(stream,'data');const trailers=once(stream,'trailers');const done=once(stream,'end');const chunks=[];stream.on('data',chunk=>chunks.push(chunk));
    stream.write(frame);
    await Promise.race([first,new Promise((_,reject)=>setTimeout(()=>reject(Error('Duplex response waited for request EOF')),5000).unref())]);
    stream.end(frame);
    const [head]=await response;assert.equal(head['x-echo-metadata'],'preserved');
    const [tail]=await trailers;await done;
    assert.deepEqual(Buffer.concat(chunks),Buffer.concat([frame,frame]));assert.equal(tail['grpc-status'],method==='Error'?'7':'0');assert.equal(tail['grpc-status-details-bin'],'AQID');
  }
  const denied=client.request({':authority':'http1.test',':method':'POST',':path':'/fixture.Service/Echo','content-type':'application/grpc'});const response=once(denied,'response');denied.resume();denied.end(frame);assert.equal((await response)[0]['grpc-status'],'12');
  const updated=await fetch(base+'/api/config',{headers});const config=await updated.json();
  config.routes[1].upstream=`https://127.0.0.1:${tlsOrigin}`;config.routes[0].upstream=config.routes[1].upstream;
  const resaved=await fetch(base+'/api/config',{method:'PUT',headers,body:JSON.stringify(config)});assert.equal(resaved.status,200,await resaved.text());
  tlsClient=http2.connect(`https://127.0.0.1:${https}`,{ca:cert,servername:'http2.test'});
  const secure=tlsClient.request({':authority':'http2.test',':method':'POST',':path':'/fixture.Service/Echo','content-type':'application/grpc'});
  const secureHead=once(secure,'response'),secureTail=once(secure,'trailers'),secureDone=once(secure,'end');const secureChunks=[];secure.on('data',chunk=>secureChunks.push(chunk));secure.end(frame);
  const [secureHeaders]=await secureHead;assert.equal(secureHeaders[':status'],200);assert.equal(secureHeaders['grpc-status'],undefined,JSON.stringify(secureHeaders));assert.equal((await secureTail)[0]['grpc-status'],'0');await secureDone;assert.deepEqual(Buffer.concat(secureChunks),frame);
  const ordinary=await new Promise((resolve,reject)=>{http.get({host:'127.0.0.1',port:proxy,headers:{Host:'auto.test'}},response=>{let body='';response.on('data',chunk=>body+=chunk);response.on('end',()=>resolve({status:response.statusCode,body}));}).on('error',reject);});assert.equal(ordinary.status,200);assert.equal(ordinary.body,'ordinary HTTP');
  const protectedConfig=await (await fetch(base+'/api/config',{headers})).json();
  protectedConfig.routes[0].access={mode:'allow',networks:['192.0.2.0/24']};
  assert.equal((await fetch(base+'/api/config',{method:'PUT',headers,body:JSON.stringify(protectedConfig)})).status,200);
  const blocked=client.request({':authority':'auto.test',':method':'POST',':path':'/fixture.Service/Echo','content-type':'application/grpc'});const blockedHead=once(blocked,'response');blocked.resume();blocked.end(frame);assert.equal((await blockedHead)[0]['grpc-status'],'7');
  console.log('gRPC smoke passed: h2c, duplex streaming, frames, metadata, trailers, errors, legacy protocol rejection, verified TLS h2 upstream and downstream, mixed HTTP/1.1, access enforcement');
} catch(error){console.error(logs);throw error;} finally {
  clearTimeout(watchdog);tlsClient?.destroy();client?.destroy();tlsBackend?.close();if(process){process.kill('SIGINT');await once(process,'exit');}backend.close();await rm(directory,{recursive:true,force:true});
}
