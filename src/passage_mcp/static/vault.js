'use strict';
const $ = id => document.getElementById(id);
let subject = null, epoch = 0, view = 0, sessionQueue = Promise.resolve();
let folderNames = [], submitAction = null;
const stale = () => new Error('Account changed. Refresh the vault.');
function clearPrivate() {
  epoch++; view++; folderNames = []; $('vault').replaceChildren();
  $('search').value = ''; closeEditor();
}
function closeEditor() {
  $('editor').close(); $('editor-form').reset(); $('fields').replaceChildren();
  submitAction = null; $('dialog-error').textContent = '';
  $('dialog-title').textContent = ''; $('dialog-note').textContent = '';
}
async function session() {
  const job = sessionQueue.then(async () => {
    let identity;
    try {
      const res = await fetch('/api/session', {cache:'no-store', credentials:'same-origin', redirect:'error'});
      if (!res.ok) throw new Error('Sign in again to open your vault.');
      identity = await res.json();
      if (typeof identity.sub !== 'string' || !identity.sub) throw new Error('Invalid account session.');
    } catch (error) {
      clearPrivate(); subject = null; $('identity').textContent = 'Sign in required';
      $('new-folder').disabled = $('trash').disabled = true; throw error;
    }
    if (identity.sub !== subject) { clearPrivate(); subject = identity.sub; }
    $('identity').textContent = identity.email || identity.name || 'Signed in';
    $('new-folder').disabled = $('trash').disabled = false;
    return subject;
  });
  sessionQueue = job.catch(() => {});
  return job;
}
async function api(path, data = {}, expected = epoch) {
  await session();
  if (epoch !== expected || !subject) throw stale();
  const boundSubject = subject;
  const res = await fetch('/api/' + path, {method:'POST', cache:'no-store', credentials:'same-origin', redirect:'error',
    headers:{'Content-Type':'application/json','X-Passage-Subject':encodeURIComponent(boundSubject)}, body:JSON.stringify(data)});
  const result = await res.json();
  await session();
  if (epoch !== expected || subject !== boundSubject) throw stale();
  if (!res.ok) throw new Error(result.error || 'Request failed.');
  return result.data;
}
function run(fn) { return async () => { try { await fn(); } catch (e) { $('status').textContent = e.message; } }; }
function button(text, action, danger=false) {
  const b = document.createElement('button'); b.type='button'; b.className='btn' + (danger?' danger':'');
  b.textContent=text; b.addEventListener('click',run(action)); return b;
}
function element(tag, text, className) {
  const e=document.createElement(tag); if(text !== undefined) e.textContent=text;
  if(className) e.className=className; return e;
}
function editor(title, specs, action, note='') {
  closeEditor(); const expected=epoch;
  $('dialog-title').textContent=title; $('dialog-note').textContent=note;
  for(const spec of specs) {
    const label=element('label',spec.label); let input;
    if(spec.options) { input=element('select'); for(const name of spec.options) { const o=element('option',name); o.value=name; input.append(o); } }
    else { input=element(spec.type==='textarea'?'textarea':'input'); if(input.tagName==='INPUT') input.type=spec.type || 'text'; }
    input.name=spec.name; input.required=spec.required !== false; input.autocomplete='off';
    input.spellcheck=false; input.value=spec.value || ''; if(spec.readonly) input.readOnly=true;
    if(spec.max) input.maxLength=spec.max;
    label.append(input); $('fields').append(label);
  }
  submitAction=action ? async data => { if(epoch!==expected) throw stale(); await action(data,expected); } : null;
  $('save').hidden=!action; $('save').disabled=false;
  $('cancel').textContent=action ? 'Cancel' : 'Close';
  $('editor').showModal(); $('fields').querySelector('input,textarea,select')?.focus();
}
function mutate(title,path,specs,base={},note='') {
  editor(title,specs,async(data,expected)=>{
    await api(path,{...base,...data},expected); closeEditor(); await refresh();
  },note);
}
const nameField = (name,label,value='') => ({name,label,value,max:200});
function secretRow(folder,name,trash=false) {
  const row=element('div',undefined,'row');
  const info=element('div'); info.append(element('strong',name),element('div',folder,'muted')); row.append(info);
  const actions=element('div',undefined,'toolbar'); const base={folder,item_name:name};
  if(trash) actions.append(button('Recover',async()=>{await api('trash/recover',base); await showTrash();}));
  else {
    actions.append(button('Reveal',async()=>{
      const expected=epoch; const record=await api('secrets/read',base,expected);
      editor(name,[{name:'username',label:'Username',value:record.username,readonly:true,required:false},
        {name:'value',label:'Secret value',value:record.password,type:'textarea',readonly:true,required:false}],null,'Close to hide this value.');
    }));
    actions.append(button('Copy',async()=>{
      const expected=epoch; const record=await api('secrets/read',base,expected);
      if(expected!==epoch) throw stale();
      await navigator.clipboard.writeText(record.password); $('status').textContent='Secret copied to clipboard.';
    }));
    actions.append(button('Edit value',()=>mutate('Replace secret value','secrets/update',[
      {name:'value',label:'New secret value',type:'textarea',required:false}],base,'The login username is preserved.')));
    actions.append(button('Rename',()=>mutate('Rename secret','secrets/rename',[nameField('new_name','New name',name)],base)));
    actions.append(button('Move',()=>mutate('Move secret','secrets/move',[{name:'target_folder',label:'Destination folder',options:folderNames.filter(f=>f!==folder)}],base)));
    actions.append(button('Delete',async()=>{if(confirm('Move “'+name+'” to trash?')) {await api('secrets/delete',base); await refresh();}},true));
  }
  row.append(actions); return row;
}
async function refresh() {
  await session(); const expected=epoch, current=++view;
  $('status').textContent='Loading vault…'; $('vault').replaceChildren();
  const folders=await api('folders/list',{},expected);
  const groups=await Promise.all(folders.map(async f=>({name:f.name,entries:await api('secrets/list',{folder:f.name},expected)})));
  if(current!==view || expected!==epoch) return;
  folderNames=folders.map(f=>f.name);
  if(!groups.length) $('vault').append(element('p','Your vault is empty. Create a folder to add your first secret.','empty'));
  for(const group of groups) {
    const section=element('section',undefined,'folder'), heading=element('div',undefined,'folder-heading');
    heading.append(element('h2',group.name));
    heading.append(button('New secret',()=>mutate('New secret','secrets/create',[
      nameField('item_name','Name'),{name:'value',label:'Secret value',type:'textarea',required:false}],{folder:group.name})));
    heading.append(button('New login',()=>mutate('New login','logins/create',[
      nameField('item_name','Name'),{name:'username',label:'Username',required:false},
      {name:'password',label:'Password',type:'password',required:false}],{folder:group.name})));
    heading.append(button('Rename folder',()=>mutate('Rename folder','folders/rename',[nameField('new_name','New name',group.name)],{folder:group.name})));
    heading.append(button('Delete folder',async()=>{if(confirm('Delete empty folder “'+group.name+'”?')) {await api('folders/delete',{folder:group.name}); await refresh();}},true));
    section.append(heading);
    const items=group.entries.flatMap(g=>g.items);
    if(!items.length) section.append(element('p','No secrets yet.','empty'));
    for(const item of items) section.append(secretRow(group.name,item.name));
    $('vault').append(section);
  }
  $('status').textContent='Vault ready.';
}
async function showTrash() {
  const current=++view, expected=epoch; const items=await api('trash/list',{},expected);
  if(current!==view || expected!==epoch) return;
  $('vault').replaceChildren(element('h2','Trash'));
  $('vault').append(button('Back to vault',refresh));
  if(!items.length) $('vault').append(element('p','Trash is empty.','empty'));
  else $('vault').append(button('Empty trash permanently',async()=>{
    if(confirm('Permanently delete every item in your trash? This cannot be undone.')) {await api('trash/empty');await showTrash();}
  },true));
  for(const item of items) $('vault').append(secretRow(item.folder,item.name,true));
  $('status').textContent='Deleted items can be recovered until trash is emptied.';
}
$('editor-form').addEventListener('submit',async e=>{
  e.preventDefault(); const action=submitAction; if(!action) return;
  $('save').disabled=true;
  try {await action(Object.fromEntries(new FormData(e.currentTarget)));}
  catch(error) {if($('editor').open) $('dialog-error').textContent=error.message; else $('status').textContent=error.message;}
  finally {$('save').disabled=false;}
});
$('cancel').addEventListener('click',closeEditor);
$('editor').addEventListener('cancel',e=>{e.preventDefault();closeEditor();});
$('new-folder').addEventListener('click',()=>mutate('Create folder','folders/create',[nameField('folder','Folder name')]));
$('refresh').addEventListener('click',run(refresh)); $('trash').addEventListener('click',run(showTrash));
$('copy-endpoint').addEventListener('click',run(async()=>{await navigator.clipboard.writeText($('endpoint').value);$('status').textContent='MCP URL copied.';}));
$('search-form').addEventListener('submit',e=>{e.preventDefault();run(async()=>{
  const query=$('search').value; if(!query.trim()) return refresh();
  const expected=epoch,current=++view; const results=await api('secrets/search',{query},expected);
  if(current!==view || expected!==epoch) return;
  $('vault').replaceChildren(element('h2','Search results'));
  for(const item of results) $('vault').append(secretRow(item.folder,item.item_name));
  $('status').textContent=results.length+' matching secrets.';
})()});
// Clear decrypted values and drafts while away; recheck account on return.
document.addEventListener('visibilitychange',()=>{
  if(document.hidden) clearPrivate(); else run(refresh)();
});
window.addEventListener('pageshow',e=>{if(e.persisted) {clearPrivate();run(refresh)();}});
run(refresh)();
