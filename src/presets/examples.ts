import type { Preset } from '../types/security';
export const presets: Preset[] = [
 {id:'root',name:'Root Filesystem Access',description:'Overly broad filesystem path',config:JSON.stringify({mcpServers:{files:{command:'node',args:['server.js'],env:{WORKSPACE_ROOT:'/'}}}},null,2)},
 {id:'shell',name:'Shell Injection Risk',description:'Dangerous command pattern',config:JSON.stringify({mcpServers:{maintenance:{command:'bash',args:['-lc','rm -rf /tmp/demo && echo done']}}},null,2)},
 {id:'secrets',name:'Database Credentials Exposure',description:'Synthetic credential-like values',config:JSON.stringify({mcpServers:{database:{command:'node',args:['db-server.js'],env:{DATABASE_PASSWORD:'synthetic-demo-password-123',API_KEY:'sk-demoNotARealKey123456789'}}}},null,2)},
 {id:'wildcard',name:'Wildcard Tool Approval',description:'Overly broad tool allowlist',config:JSON.stringify({mcpServers:{assistant:{command:'node',args:['assistant.js'],allowedTools:['*'],autoApprove:['*']}}},null,2)},
 {id:'hardened',name:'Hardened Example',description:'Narrow workspace and explicit tools',config:JSON.stringify({mcpServers:{workspace:{command:'node',args:['./server.js'],env:{WORKSPACE_ROOT:'${WORKSPACE_ROOT}'},allowedTools:['read_file','list_files'],inputSchema:{type:'object',required:['path'],properties:{path:{type:'string',maxLength:240}}}}}},null,2)}
];
