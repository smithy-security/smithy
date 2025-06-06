
�������bandit�
./bad/api_list.py:10B113request_without_timeout 0:�Requests call without timeout
code:9 
10     r = requests.get('http://127.0.1.1:5000/api/post/{}'.format(username))
11     if r.status_code != 200:
Bunknownb j��
./bad/api_post.py:6B108hardcoded_tmp_directory 0:iProbable insecure usage of temp file/directory.
code:5 
6 api_key_file = Path('/tmp/supersecret.txt')
7 
Bunknownb j��
./bad/api_post.py:16B113request_without_timeout 0:�Requests call without timeout
code:15 
16         r = requests.post('http://127.0.1.1:5000/api/key', json={'username':username, 'password':password})
17 
Bunknownb j��
./bad/api_post.py:30B113request_without_timeout 0:�Requests call without timeout
code:29     api_key = api_key_file.open().read()
30     r = requests.post('http://127.0.1.1:5000/api/post', json={'text':message}, headers={'X-APIKEY': api_key})
31     print(r.text)
Bunknownb j��
./bad/brute.py:3B404	blacklist 0:xConsider possible security implications associated with the subprocess module.
code:2 
3 import subprocess
4 import sys
Bunknownb jN�
./bad/brute.py:21B603$subprocess_without_shell_equals_true 0:�subprocess call - check for execution of untrusted input.
code:20 for password in passwords:
21     result = subprocess.run([program, username, password], stdout=subprocess.DEVNULL)
22     if result.returncode == 0:
Bunknownb jN�
./bad/db.py:19B608hardcoded_sql_expressions 0:�Possible SQL injection vector through string-based query construction.
code:18     for u,p in users:
19         c.execute("INSERT INTO users (user, password, failures) VALUES ('%s', '%s', '%d')" %(u, p, 0))
20 
Bunknownb jY�
./bad/db_init.py:20B608hardcoded_sql_expressions 0:�Possible SQL injection vector through string-based query construction.
code:19     for u,p in users:
20         c.execute("INSERT INTO users (username, password, failures, mfa_enabled, mfa_secret) VALUES ('%s', '%s', '%d', '%d', '%s')" %(u, p, 0, 0, ''))
21 
Bunknownb jY�
./bad/libapi.py:16B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:15 
16     for f in Path('/tmp/').glob('vulpy.apikey.' + username + '.*'):
17         print('removing', f)
Bunknownb j��
./bad/libapi.py:20B108hardcoded_tmp_directory 0:~Probable insecure usage of temp file/directory.
code:19 
20     keyfile = '/tmp/vulpy.apikey.{}.{}'.format(username, key)
21 
Bunknownb j��
./bad/libapi.py:33B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:32 
33     for f in Path('/tmp/').glob('vulpy.apikey.*.' + key):
34         return f.name.split('.')[2]
Bunknownb j��
./bad/libsession.py:21-22B110try_except_pass 0:�Try, Except, Pass detected.
code:20                 session = json.loads(base64.b64decode(cookie))
21     except Exception:
22         pass
23 
Bunknownb j��
./bad/libuser.py:12B608hardcoded_sql_expressions 0:�Possible SQL injection vector through string-based query construction.
code:11 
12     user = c.execute("SELECT * FROM users WHERE username = '{}' and password = '{}'".format(username, password)).fetchone()
13 
Bunknownb jY�
./bad/libuser.py:25B608hardcoded_sql_expressions 0:�Possible SQL injection vector through string-based query construction.
code:24 
25     c.execute("INSERT INTO users (username, password, failures, mfa_enabled, mfa_secret) VALUES ('%s', '%s', '%d', '%d', '%s')" %(username, password, 0, 0, ''))
26 
Bunknownb jY�
./bad/libuser.py:53B608hardcoded_sql_expressions 0:�Possible SQL injection vector through string-based query construction.
code:52 
53     c.execute("UPDATE users SET password = '{}' WHERE username = '{}'".format(password, username))
54     conn.commit()
Bunknownb jY�
./bad/vulpy-ssl.py:13B105hardcoded_password_string 0:pPossible hardcoded password: 'aaaaaaa'
code:12 app = Flask('vulpy')
13 app.config['SECRET_KEY'] = 'aaaaaaa'
14 
Bunknownb j��
./bad/vulpy-ssl.py:29B201flask_debug_true 0:�A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.
code:28 
29 app.run(debug=True, host='127.0.1.1', ssl_context=('/tmp/acme.cert', '/tmp/acme.key'))
Bunknownb j^�
./bad/vulpy-ssl.py:29B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:28 
29 app.run(debug=True, host='127.0.1.1', ssl_context=('/tmp/acme.cert', '/tmp/acme.key'))
Bunknownb j��
./bad/vulpy-ssl.py:29B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:28 
29 app.run(debug=True, host='127.0.1.1', ssl_context=('/tmp/acme.cert', '/tmp/acme.key'))
Bunknownb j��
./bad/vulpy.py:16B105hardcoded_password_string 0:pPossible hardcoded password: 'aaaaaaa'
code:15 app = Flask('vulpy')
16 app.config['SECRET_KEY'] = 'aaaaaaa'
17 
Bunknownb j��
./bad/vulpy.py:55B201flask_debug_true 0:�A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.
code:54 
55 app.run(debug=True, host='127.0.1.1', port=5000, extra_files='csp.txt')
Bunknownb j^�
B./bandit-env/lib/python3.12/site-packages/markdown_it/ruler.py:266B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:265             self.__compile__()
266             assert self.__cache__ is not None
267         # Chain can be empty, if rules disabled. But we still have to return Array.
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/markdown_it/rules_core/linkify.py:35B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:34         # Use reversed logic in links start/end match
35         assert tokens is not None
36         i = len(tokens)
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/markdown_it/rules_core/linkify.py:39B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:38             i -= 1
39             assert isinstance(tokens, list)
40             currentToken = tokens[i]
Bunknownb j��
R./bandit-env/lib/python3.12/site-packages/markdown_it/rules_core/smartquotes.py:20B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:19     # But basically, the index will not be negative.
20     assert index >= 0
21     return string[:index] + ch + string[index + 1 :]
Bunknownb j��
A./bandit-env/lib/python3.12/site-packages/markdown_it/tree.py:101B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:100             else:
101                 assert node.nester_tokens
102                 token_list.append(node.nester_tokens.opening)
Bunknownb j��
A./bandit-env/lib/python3.12/site-packages/markdown_it/tree.py:165B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:164             return self.token.type
165         assert self.nester_tokens
166         return _removesuffix(self.nester_tokens.opening.type, "_open")
Bunknownb j��
7./bandit-env/lib/python3.12/site-packages/pbr/git.py:25B404	blacklist 0:�Consider possible security implications associated with the subprocess module.
code:24 import re
25 import subprocess
26 import time
Bunknownb jN�
@./bandit-env/lib/python3.12/site-packages/pbr/git.py:46-47-48-49B603$subprocess_without_shell_equals_true 0:�subprocess call - check for execution of untrusted input.
code:45 
46     output = subprocess.Popen(cmd,
47                               stdout=out_location,
48                               stderr=err_location,
49                               env=newenv)
50     out = output.communicate()
Bunknownb jN�
B./bandit-env/lib/python3.12/site-packages/pbr/packaging.py:729-730B110try_except_pass 0:�Try, Except, Pass detected.
code:728                 version_tags.add(semver)
729             except Exception:
730                 pass
731         if version_tags:
Bunknownb j��
B./bandit-env/lib/python3.12/site-packages/pbr/testr_command.py:142B605start_process_with_a_shell 0:�Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell
code:141         logger.debug("_coverage_after called")
142         os.system("coverage combine")
143         os.system("coverage html -d ./cover %s" % self.omit)
Bunknownb jN�
B./bandit-env/lib/python3.12/site-packages/pbr/testr_command.py:142B607start_process_with_partial_path 0:�Starting a process with a partial executable path
code:141         logger.debug("_coverage_after called")
142         os.system("coverage combine")
143         os.system("coverage html -d ./cover %s" % self.omit)
Bunknownb jN�
B./bandit-env/lib/python3.12/site-packages/pbr/testr_command.py:143B605start_process_with_a_shell 0:�Starting a process with a shell, possible injection detected, security issue.
code:142         os.system("coverage combine")
143         os.system("coverage html -d ./cover %s" % self.omit)
144         os.system("coverage xml -o ./cover/coverage.xml %s" % self.omit)
Bunknownb jN�
B./bandit-env/lib/python3.12/site-packages/pbr/testr_command.py:144B605start_process_with_a_shell 0:�Starting a process with a shell, possible injection detected, security issue.
code:143         os.system("coverage html -d ./cover %s" % self.omit)
144         os.system("coverage xml -o ./cover/coverage.xml %s" % self.omit)
145 
Bunknownb jN�
>./bandit-env/lib/python3.12/site-packages/pbr/tests/base.py:44B404	blacklist 0:�Consider possible security implications associated with the subprocess module.
code:43 import shutil
44 import subprocess
45 import sys
Bunknownb jN�
?./bandit-env/lib/python3.12/site-packages/pbr/tests/base.py:182B603$subprocess_without_shell_equals_true 0:�subprocess call - check for execution of untrusted input.
code:181         super(CapturedSubprocess, self).setUp()
182         proc = subprocess.Popen(*self.args, **self.kwargs)
183         out, err = proc.communicate()
Bunknownb jN�
G./bandit-env/lib/python3.12/site-packages/pbr/tests/base.py:206-207-208B603$subprocess_without_shell_equals_true 0:�subprocess call - check for execution of untrusted input.
code:205     print('Running %s' % ' '.join(args))
206     p = subprocess.Popen(
207         args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
208         stderr=subprocess.PIPE, cwd=cwd)
209     streams = tuple(s.decode('latin1').strip() for s in p.communicate())
Bunknownb jN�
C./bandit-env/lib/python3.12/site-packages/pbr/tests/test_core.py:78B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:77         stdout, _, _ = self.run_setup('--keywords')
78         assert stdout == 'packaging, distutils, setuptools'
79 
Bunknownb j��
C./bandit-env/lib/python3.12/site-packages/pbr/tests/test_core.py:89B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:88         except IndexError:
89             assert False, 'source dist not found'
90 
Bunknownb j��
D./bandit-env/lib/python3.12/site-packages/pbr/tests/test_hooks.py:68B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:67         stdout, _, return_code = self.run_setup('egg_info')
68         assert 'test_hook_1\ntest_hook_2' in stdout
69         assert return_code == 0
Bunknownb j��
D./bandit-env/lib/python3.12/site-packages/pbr/tests/test_hooks.py:69B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:68         assert 'test_hook_1\ntest_hook_2' in stdout
69         assert return_code == 0
70 
Bunknownb j��
C./bandit-env/lib/python3.12/site-packages/pbr/tests/test_wsgi.py:17B404	blacklist 0:�Consider possible security implications associated with the subprocess module.
code:16 import re
17 import subprocess
18 import sys
Bunknownb jN�
I./bandit-env/lib/python3.12/site-packages/pbr/tests/test_wsgi.py:87-88-89B603$subprocess_without_shell_equals_true 0:�subprocess call - check for execution of untrusted input.
code:86 
87         p = subprocess.Popen(popen_cmd, stdout=subprocess.PIPE,
88                              stderr=subprocess.PIPE, cwd=self.temp_dir,
89                              env=env)
90         self.addCleanup(p.kill)
Bunknownb jN�
D./bandit-env/lib/python3.12/site-packages/pbr/tests/test_wsgi.py:111B310	blacklist 0:�Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.
code:110 
111         f = urlopen(m.group(1).decode('utf-8'))
112         self.assertEqual(output, f.read())
Bunknownb j�
D./bandit-env/lib/python3.12/site-packages/pbr/tests/test_wsgi.py:116B310	blacklist 0:�Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.
code:115         # otherwise the log is buffered and the next readline() will hang.
116         urlopen(m.group(1).decode('utf-8'))
117 
Bunknownb j�
B./bandit-env/lib/python3.12/site-packages/pip/__pip-runner__.py:43B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:42         spec = PathFinder.find_spec(fullname, [PIP_SOURCES_ROOT], target)
43         assert spec, (PIP_SOURCES_ROOT, fullname)
44         return spec
Bunknownb j��
B./bandit-env/lib/python3.12/site-packages/pip/__pip-runner__.py:49B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:48 
49 assert __name__ == "__main__", "Cannot run __pip-runner__.py as a non-main module"
50 runpy.run_module("pip", run_name="__main__", alter_sys=True)
Bunknownb j��
H./bandit-env/lib/python3.12/site-packages/pip/_internal/build_env.py:214B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:213         prefix = self._prefixes[prefix_as_string]
214         assert not prefix.setup
215         prefix.setup = True
Bunknownb j��
C./bandit-env/lib/python3.12/site-packages/pip/_internal/cache.py:40B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:39         super().__init__()
40         assert not cache_dir or os.path.isabs(cache_dir)
41         self.cache_dir = cache_dir or None
Bunknownb j��
D./bandit-env/lib/python3.12/site-packages/pip/_internal/cache.py:124B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:123         parts = self._get_cache_path_parts(link)
124         assert self.cache_dir
125         # Store wheels within the root cache_dir
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/cli/base_command.py:88B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:87         # are present.
88         assert not hasattr(options, "no_index")
89 
Bunknownb j��
O./bandit-env/lib/python3.12/site-packages/pip/_internal/cli/base_command.py:106B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:105             status = _inner_run()
106             assert isinstance(status, int)
107             return status
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_internal/cli/command_context.py:15B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:14     def main_context(self) -> Generator[None, None, None]:
15         assert not self._in_main_context
16 
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_internal/cli/command_context.py:25B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:24     def enter_context(self, context_provider: ContextManager[_T]) -> _T:
25         assert self._in_main_context
26 
Bunknownb j��
O./bandit-env/lib/python3.12/site-packages/pip/_internal/cli/index_command.py:80B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:79             # then https://github.com/python/mypy/issues/7696 kicks in
80             assert self._session is not None
81         return self._session
Bunknownb j��
O./bandit-env/lib/python3.12/site-packages/pip/_internal/cli/index_command.py:92B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:91         cache_dir = options.cache_dir
92         assert not cache_dir or os.path.isabs(cache_dir)
93 
Bunknownb j��
P./bandit-env/lib/python3.12/site-packages/pip/_internal/cli/index_command.py:154B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:153         # Make sure the index_group options are present.
154         assert hasattr(options, "no_index")
155 
Bunknownb j��
L./bandit-env/lib/python3.12/site-packages/pip/_internal/cli/main_parser.py:5B404	blacklist 0:�Consider possible security implications associated with the subprocess module.
code:4 import os
5 import subprocess
6 import sys
Bunknownb jN�
N./bandit-env/lib/python3.12/site-packages/pip/_internal/cli/main_parser.py:101B603$subprocess_without_shell_equals_true 0:�subprocess call - check for execution of untrusted input.
code:100         try:
101             proc = subprocess.run(pip_cmd)
102             returncode = proc.returncode
Bunknownb jN�
H./bandit-env/lib/python3.12/site-packages/pip/_internal/cli/parser.py:51B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:50         if option.takes_value():
51             assert option.dest is not None
52             metavar = option.metavar or option.dest.lower()
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pip/_internal/cli/parser.py:112B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:111         if self.parser is not None:
112             assert isinstance(self.parser, ConfigOptionParser)
113             self.parser._update_defaults(self.parser.defaults)
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pip/_internal/cli/parser.py:114B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:113             self.parser._update_defaults(self.parser.defaults)
114             assert option.dest is not None
115             default_values = self.parser.defaults.get(option.dest)
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pip/_internal/cli/parser.py:168B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:167 
168         assert self.name
169         super().__init__(*args, **kwargs)
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pip/_internal/cli/parser.py:225B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:224 
225             assert option.dest is not None
226 
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pip/_internal/cli/parser.py:252B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:251             elif option.action == "callback":
252                 assert option.callback is not None
253                 late_eval.add(option.dest)
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pip/_internal/cli/parser.py:285B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:284         for option in self._get_all_options():
285             assert option.dest is not None
286             default = defaults.get(option.dest)
Bunknownb j��
O./bandit-env/lib/python3.12/site-packages/pip/_internal/cli/progress_bars.py:30B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:29 ) -> Generator[bytes, None, None]:
30     assert bar_type == "on", "This should only be used in the default mode."
31 
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pip/_internal/cli/req_command.py:62B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:61     ) -> Optional[int]:
62         assert self.tempdir_registry is not None
63         if options.no_clean:
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/cli/req_command.py:108B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:107         temp_build_dir_path = temp_build_dir.path
108         assert temp_build_dir_path is not None
109         legacy_resolver = False
Bunknownb j��
J./bandit-env/lib/python3.12/site-packages/pip/_internal/cli/spinners.py:44B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:43     def _write(self, status: str) -> None:
44         assert not self._finished
45         # Erase what we wrote before by backspacing to the beginning, writing
Bunknownb j��
J./bandit-env/lib/python3.12/site-packages/pip/_internal/cli/spinners.py:83B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:82     def _update(self, status: str) -> None:
83         assert not self._finished
84         self._rate_limiter.reset()
Bunknownb j��
R./bandit-env/lib/python3.12/site-packages/pip/_internal/commands/completion.py:124B604)any_other_function_with_shell_equals_true 0:�Function call with shell=True parameter identified, possible security issue.
code:123             )
124             print(BASE_COMPLETION.format(script=script, shell=options.shell))
125             return SUCCESS
Bunknownb jN�
S./bandit-env/lib/python3.12/site-packages/pip/_internal/commands/configuration.py:3B404	blacklist 0:�Consider possible security implications associated with the subprocess module.
code:2 import os
3 import subprocess
4 from optparse import Values
Bunknownb jN�
U./bandit-env/lib/python3.12/site-packages/pip/_internal/commands/configuration.py:239B602'subprocess_popen_with_shell_equals_true 0:�subprocess call with shell=True identified, security issue.
code:238         try:
239             subprocess.check_call(f'{editor} "{fname}"', shell=True)
240         except FileNotFoundError as e:
Bunknownb jN�
L./bandit-env/lib/python3.12/site-packages/pip/_internal/commands/debug.py:73B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:72         # Try to find version in debundled module info.
73         assert module.__file__ is not None
74         env = get_environment([os.path.dirname(module.__file__)])
Bunknownb j��
P./bandit-env/lib/python3.12/site-packages/pip/_internal/commands/download.py:137B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:136             if req.satisfied_by is None:
137                 assert req.name is not None
138                 preparer.save_linked_requirement(req)
Bunknownb j��
O./bandit-env/lib/python3.12/site-packages/pip/_internal/commands/install.py:518B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:517         if options.target_dir:
518             assert target_temp_dir
519             self._handle_target_dir(
Bunknownb j��
O./bandit-env/lib/python3.12/site-packages/pip/_internal/commands/install.py:607B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:606         else:
607             assert resolver_variant == "resolvelib"
608             parts.append(
Bunknownb j��
O./bandit-env/lib/python3.12/site-packages/pip/_internal/commands/install.py:704B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:703     # If we are here, user installs have not been explicitly requested/avoided
704     assert use_user_site is None
705 
Bunknownb j��
L./bandit-env/lib/python3.12/site-packages/pip/_internal/commands/search.py:5B411	blacklist 0:�Using xmlrpc.client to parse untrusted XML data is known to be vulnerable to XML attacks. Use defusedxml.xmlrpc.monkey_patch() function to monkey-patch xmlrpclib and mitigate XML vulnerabilities.
code:4 import textwrap
5 import xmlrpc.client
6 from collections import OrderedDict
Bunknownb j�
M./bandit-env/lib/python3.12/site-packages/pip/_internal/commands/search.py:82B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:81             raise CommandError(message)
82         assert isinstance(hits, list)
83         return hits
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pip/_internal/commands/wheel.py:167B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:166         for req in build_successes:
167             assert req.link and req.link.is_wheel
168             assert req.local_file_path
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pip/_internal/commands/wheel.py:168B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:167             assert req.link and req.link.is_wheel
168             assert req.local_file_path
169             # copy from cache to target directory
Bunknownb j��
L./bandit-env/lib/python3.12/site-packages/pip/_internal/configuration.py:130B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:129         """Returns the file with highest priority in configuration"""
130         assert self.load_only is not None, "Need to be specified a file to be editing"
131 
Bunknownb j��
L./bandit-env/lib/python3.12/site-packages/pip/_internal/configuration.py:160B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:159 
160         assert self.load_only
161         fname, parser = self._get_parser_to_modify()
Bunknownb j��
L./bandit-env/lib/python3.12/site-packages/pip/_internal/configuration.py:180B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:179 
180         assert self.load_only
181         if key not in self._config[self.load_only]:
Bunknownb j��
L./bandit-env/lib/python3.12/site-packages/pip/_internal/configuration.py:365B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:364         # Determine which parser to modify
365         assert self.load_only
366         parsers = self._parsers[self.load_only]
Bunknownb j��
U./bandit-env/lib/python3.12/site-packages/pip/_internal/distributions/installed.py:20B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:19     def get_metadata_distribution(self) -> BaseDistribution:
20         assert self.req.satisfied_by is not None, "not actually installed"
21         return self.req.satisfied_by
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_internal/distributions/sdist.py:26B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:25         """Identify this requirement uniquely by its link."""
26         assert self.req.link
27         return self.req.link.url_without_fragment
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_internal/distributions/sdist.py:61B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:60             pyproject_requires = self.req.pyproject_requires
61             assert pyproject_requires is not None
62             conflicting, missing = self.req.build_env.check_requirements(
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_internal/distributions/sdist.py:75B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:74         pyproject_requires = self.req.pyproject_requires
75         assert pyproject_requires is not None
76 
Bunknownb j��
R./bandit-env/lib/python3.12/site-packages/pip/_internal/distributions/sdist.py:101B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:100             backend = self.req.pep517_backend
101             assert backend is not None
102             with backend.subprocess_runner(runner):
Bunknownb j��
R./bandit-env/lib/python3.12/site-packages/pip/_internal/distributions/sdist.py:111B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:110             backend = self.req.pep517_backend
111             assert backend is not None
112             with backend.subprocess_runner(runner):
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_internal/distributions/wheel.py:31B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:30         """
31         assert self.req.local_file_path, "Set as part of preparation during download"
32         assert self.req.name, "Wheels are never unnamed"
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_internal/distributions/wheel.py:32B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:31         assert self.req.local_file_path, "Set as part of preparation during download"
32         assert self.req.name, "Wheels are never unnamed"
33         wheel = FilesystemWheel(self.req.local_file_path)
Bunknownb j��
H./bandit-env/lib/python3.12/site-packages/pip/_internal/exceptions.py:87B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:86         if reference is None:
87             assert hasattr(self, "reference"), "error reference not provided!"
88             reference = self.reference
Bunknownb j��
H./bandit-env/lib/python3.12/site-packages/pip/_internal/exceptions.py:89B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:88             reference = self.reference
89         assert _is_kebab_case(reference), "error reference must be kebab-case!"
90 
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pip/_internal/exceptions.py:653B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:652         else:
653             assert self.error is not None
654             message_part = f".\n{self.error}\n"
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/index/collector.py:189B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:188     def __init__(self, page: "IndexContent") -> None:
189         assert page.cache_link_parsing
190         self.page = page
Bunknownb j��
S./bandit-env/lib/python3.12/site-packages/pip/_internal/index/package_finder.py:356B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:355         """
356         assert set(applicable_candidates) <= set(candidates)
357 
Bunknownb j��
S./bandit-env/lib/python3.12/site-packages/pip/_internal/index/package_finder.py:359B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:358         if best_candidate is None:
359             assert not applicable_candidates
360         else:
Bunknownb j��
S./bandit-env/lib/python3.12/site-packages/pip/_internal/index/package_finder.py:361B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:360         else:
361             assert best_candidate in applicable_candidates
362 
Bunknownb j��
S./bandit-env/lib/python3.12/site-packages/pip/_internal/index/package_finder.py:533B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:532                 match = re.match(r"^(\d+)(.*)$", wheel.build_tag)
533                 assert match is not None, "guaranteed by filename validation"
534                 build_tag_groups = match.groups()
Bunknownb j��
S./bandit-env/lib/python3.12/site-packages/pip/_internal/index/package_finder.py:840B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:839             for candidate in file_candidates:
840                 assert candidate.link.url  # we need to have a URL
841                 try:
Bunknownb j��
R./bandit-env/lib/python3.12/site-packages/pip/_internal/locations/_distutils.py:66B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:65     obj = d.get_command_obj("install", create=True)
66     assert obj is not None
67     i = cast(distutils_install_command, obj)
Bunknownb j��
R./bandit-env/lib/python3.12/site-packages/pip/_internal/locations/_distutils.py:71B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:70     # ideally, we'd prefer a scheme class that has no side-effects.
71     assert not (user and prefix), f"user={user} prefix={prefix}"
72     assert not (home and prefix), f"home={home} prefix={prefix}"
Bunknownb j��
R./bandit-env/lib/python3.12/site-packages/pip/_internal/locations/_distutils.py:72B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:71     assert not (user and prefix), f"user={user} prefix={prefix}"
72     assert not (home and prefix), f"home={home} prefix={prefix}"
73     i.user = user or i.user
Bunknownb j��
U./bandit-env/lib/python3.12/site-packages/pip/_internal/metadata/pkg_resources.py:112B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:111         else:
112             assert dist_dir.endswith(".dist-info")
113             dist_cls = pkg_resources.DistInfoDistribution
Bunknownb j��
O./bandit-env/lib/python3.12/site-packages/pip/_internal/models/direct_url.py:60B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:59         )
60     assert infos[0] is not None
61     return infos[0]
Bunknownb j��
P./bandit-env/lib/python3.12/site-packages/pip/_internal/models/direct_url.py:171B105hardcoded_password_string 0:�Possible hardcoded password: 'git'
code:170             and self.info.vcs == "git"
171             and user_pass == "git"
172         ):
Bunknownb j��
X./bandit-env/lib/python3.12/site-packages/pip/_internal/models/installation_report.py:15B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:14     def _install_req_to_dict(cls, ireq: InstallRequirement) -> Dict[str, Any]:
15         assert ireq.download_info, f"No download_info for {ireq}"
16         res = {
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pip/_internal/models/link.py:69B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:68     def __post_init__(self) -> None:
69         assert self.name in _SUPPORTED_HASHES
70 
Bunknownb j��
J./bandit-env/lib/python3.12/site-packages/pip/_internal/models/link.py:105B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:104         if self.hashes is not None:
105             assert all(name in _SUPPORTED_HASHES for name in self.hashes)
106 
Bunknownb j��
J./bandit-env/lib/python3.12/site-packages/pip/_internal/models/link.py:404B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:403         name = urllib.parse.unquote(name)
404         assert name, f"URL {self._url!r} produced no filename"
405         return name
Bunknownb j��
J./bandit-env/lib/python3.12/site-packages/pip/_internal/network/auth.py:10B404	blacklist 0:�Consider possible security implications associated with the subprocess module.
code:9 import shutil
10 import subprocess
11 import sysconfig
Bunknownb jN�
_./bandit-env/lib/python3.12/site-packages/pip/_internal/network/auth.py:137-138-139-140-141-142B603$subprocess_without_shell_equals_true 0:�subprocess call - check for execution of untrusted input.
code:136         env["PYTHONIOENCODING"] = "utf-8"
137         res = subprocess.run(
138             cmd,
139             stdin=subprocess.DEVNULL,
140             stdout=subprocess.PIPE,
141             env=env,
142         )
143         if res.returncode:
Bunknownb jN�
_./bandit-env/lib/python3.12/site-packages/pip/_internal/network/auth.py:153-154-155-156-157-158B603$subprocess_without_shell_equals_true 0:�subprocess call - check for execution of untrusted input.
code:152         env["PYTHONIOENCODING"] = "utf-8"
153         subprocess.run(
154             [self.keyring, "set", service_name, username],
155             input=f"{password}{os.linesep}".encode(),
156             env=env,
157             check=True,
158         )
159         return None
Bunknownb jN�
_./bandit-env/lib/python3.12/site-packages/pip/_internal/network/auth.py:431-432-433-434-435-436B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:430 
431         assert (
432             # Credentials were found
433             (username is not None and password is not None)
434             # Credentials were not found
435             or (username is None and password is None)
436         ), f"Could not load credentials from url: {original_url}"
437 
Bunknownb j��
S./bandit-env/lib/python3.12/site-packages/pip/_internal/network/auth.py:553-554-555B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:552         """Response callback to save credentials on success."""
553         assert (
554             self.keyring_provider.has_keyring
555         ), "should never reach here without keyring"
556 
Bunknownb j��
K./bandit-env/lib/python3.12/site-packages/pip/_internal/network/cache.py:51B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:50     def __init__(self, directory: str) -> None:
51         assert directory is not None, "Cache directory must not be None."
52         super().__init__()
Bunknownb j��
O./bandit-env/lib/python3.12/site-packages/pip/_internal/network/download.py:137B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:136         except NetworkConnectionError as e:
137             assert e.response is not None
138             logger.critical(
Bunknownb j��
O./bandit-env/lib/python3.12/site-packages/pip/_internal/network/download.py:171B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:170             except NetworkConnectionError as e:
171                 assert e.response is not None
172                 logger.critical(
Bunknownb j��
P./bandit-env/lib/python3.12/site-packages/pip/_internal/network/lazy_wheel.py:54B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:53         raise_for_status(head)
54         assert head.status_code == 200
55         self._session, self._url, self._chunk_size = session, url, chunk_size
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pip/_internal/network/session.py:15B404	blacklist 0:�Consider possible security implications associated with the subprocess module.
code:14 import shutil
15 import subprocess
16 import sys
Bunknownb jN�
V./bandit-env/lib/python3.12/site-packages/pip/_internal/network/session.py:184-185-186B607start_process_with_partial_path 0:�Starting a process with a partial executable path
code:183         try:
184             rustc_output = subprocess.check_output(
185                 ["rustc", "--version"], stderr=subprocess.STDOUT, timeout=0.5
186             )
187         except Exception:
Bunknownb jN�
V./bandit-env/lib/python3.12/site-packages/pip/_internal/network/session.py:184-185-186B603$subprocess_without_shell_equals_true 0:�subprocess call - check for execution of untrusted input.
code:183         try:
184             rustc_output = subprocess.check_output(
185                 ["rustc", "--version"], stderr=subprocess.STDOUT, timeout=0.5
186             )
187         except Exception:
Bunknownb jN�
R./bandit-env/lib/python3.12/site-packages/pip/_internal/network/session.py:187-188B110try_except_pass 0:xTry, Except, Pass detected.
code:186             )
187         except Exception:
188             pass
189         else:
Bunknownb j��
K./bandit-env/lib/python3.12/site-packages/pip/_internal/network/xmlrpc.py:6B411	blacklist 0:�Using xmlrpc.client to parse untrusted XML data is known to be vulnerable to XML attacks. Use defusedxml.xmlrpc.monkey_patch() function to monkey-patch xmlrpclib and mitigate XML vulnerabilities.
code:5 import urllib.parse
6 import xmlrpc.client
7 from typing import TYPE_CHECKING, Tuple
Bunknownb j�
L./bandit-env/lib/python3.12/site-packages/pip/_internal/network/xmlrpc.py:14B411	blacklist 0:�Using _HostType to parse untrusted XML data is known to be vulnerable to XML attacks. Use defusedxml.xmlrpc.monkey_patch() function to monkey-patch xmlrpclib and mitigate XML vulnerabilities.
code:13 if TYPE_CHECKING:
14     from xmlrpc.client import _HostType, _Marshallable
15 
Bunknownb j�
L./bandit-env/lib/python3.12/site-packages/pip/_internal/network/xmlrpc.py:41B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:40     ) -> Tuple["_Marshallable", ...]:
41         assert isinstance(host, str)
42         parts = (self._scheme, host, handler, None, None, None)
Bunknownb j��
L./bandit-env/lib/python3.12/site-packages/pip/_internal/network/xmlrpc.py:56B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:55         except NetworkConnectionError as exc:
56             assert exc.response
57             logger.critical(
Bunknownb j��
\./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/build/build_tracker.py:36B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:35             else:
36                 assert isinstance(original_value, str)  # for mypy
37                 target[name] = original_value
Bunknownb j��
]./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/build/build_tracker.py:105B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:104         # If we're here, req should really not be building already.
105         assert key not in self._entries
106 
Bunknownb j��
T./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/build/wheel.py:22B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:21     """
22     assert metadata_directory is not None
23     try:
Bunknownb j��
]./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/build/wheel_editable.py:22B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:21     """
22     assert metadata_directory is not None
23     try:
Bunknownb j��
P./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/freeze.py:163B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:162     editable_project_location = dist.editable_project_location
163     assert editable_project_location
164     location = os.path.normcase(os.path.abspath(editable_project_location))
Bunknownb j��
V./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/install/wheel.py:99B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:98     # XXX RECORD hashes will need to be updated
99     assert os.path.isfile(path)
100 
Bunknownb j��
W./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/install/wheel.py:621B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:620                         pyc_path = pyc_output_path(path)
621                         assert os.path.exists(pyc_path)
622                         pyc_record_path = cast(
Bunknownb j��
P./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/prepare.py:80B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:79     vcs_backend = vcs.get_backend_for_scheme(link.scheme)
80     assert vcs_backend is not None
81     vcs_backend.unpack(location, url=hide_url(link.url), verbosity=verbosity)
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/prepare.py:162B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:161 
162     assert not link.is_existing_dir()
163 
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/prepare.py:312B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:311             return
312         assert req.source_dir is None
313         if req.link.is_existing_dir():
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/prepare.py:386B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:385             return None
386         assert req.req is not None
387         logger.verbose(
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/prepare.py:462B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:461         for req in partially_downloaded_reqs:
462             assert req.link
463             links_to_fully_download[req.link] = req
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/prepare.py:495B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:494         """Prepare a requirement to be obtained from req.link."""
495         assert req.link
496         self._log_preparing_link(req)
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/prepare.py:562B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:561     ) -> BaseDistribution:
562         assert req.link
563         link = req.link
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/prepare.py:568B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:567         if hashes and req.is_wheel_from_cache:
568             assert req.download_info is not None
569             assert link.is_wheel
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/prepare.py:569B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:568             assert req.download_info is not None
569             assert link.is_wheel
570             assert link.is_file
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/prepare.py:570B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:569             assert link.is_wheel
570             assert link.is_file
571             # We need to verify hashes, and we have found the requirement in the cache
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/prepare.py:621B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:620             # prepare_editable_requirement).
621             assert not req.editable
622             req.download_info = direct_url_from_link(link, req.source_dir)
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/prepare.py:652B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:651     def save_linked_requirement(self, req: InstallRequirement) -> None:
652         assert self.download_dir is not None
653         assert req.link is not None
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/prepare.py:653B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:652         assert self.download_dir is not None
653         assert req.link is not None
654         link = req.link
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/prepare.py:682B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:681         """Prepare an editable requirement."""
682         assert req.editable, "cannot prepare a non-editable req as editable"
683 
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/prepare.py:695B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:694             req.update_editable()
695             assert req.source_dir
696             req.download_info = direct_url_for_editable(req.unpacked_source_directory)
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/prepare.py:716B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:715         """Prepare an already-installed requirement."""
716         assert req.satisfied_by, "req should have been satisfied but isn't"
717         assert skip_reason is not None, (
Bunknownb j��
]./bandit-env/lib/python3.12/site-packages/pip/_internal/operations/prepare.py:717-718-719-720B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:716         assert req.satisfied_by, "req should have been satisfied but isn't"
717         assert skip_reason is not None, (
718             "did not get skip reason skipped but req.satisfied_by "
719             f"is set to {req.satisfied_by}"
720         )
721         logger.info(
Bunknownb j��
H./bandit-env/lib/python3.12/site-packages/pip/_internal/pyproject.py:115B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:114     # At this point, we know whether we're going to use PEP 517.
115     assert use_pep517 is not None
116 
Bunknownb j��
H./bandit-env/lib/python3.12/site-packages/pip/_internal/pyproject.py:140B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:139     # specified a backend, though.
140     assert build_system is not None
141 
Bunknownb j��
J./bandit-env/lib/python3.12/site-packages/pip/_internal/req/__init__.py:31B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:30     for req in requirements:
31         assert req.name, f"invalid to-be-installed requirement: {req}"
32         yield req.name, req
Bunknownb j��
T./bandit-env/lib/python3.12/site-packages/pip/_internal/req/constructors.py:75-76-77B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:74     # ireq.req is a valid requirement so the regex should always match
75     assert (
76         match is not None
77     ), f"regex match on requirement {req} failed, this should never happen"
78     pre: Optional[str] = match.group(1)
Bunknownb j��
T./bandit-env/lib/python3.12/site-packages/pip/_internal/req/constructors.py:80-81-82B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:79     post: Optional[str] = match.group(3)
80     assert (
81         pre is not None and post is not None
82     ), f"regex group selection for requirement {req} failed, this should never happen"
83     extras: str = "[%s]" % ",".join(sorted(new_extras)) if new_extras else ""
Bunknownb j��
K./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_file.py:182B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:181 
182     assert line.is_requirement
183 
Bunknownb j��
K./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_file.py:471B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:470                 new_line.append(line)
471                 assert primary_line_number is not None
472                 yield primary_line_number, "".join(new_line)
Bunknownb j��
K./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_file.py:483B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:482     if new_line:
483         assert primary_line_number is not None
484         yield primary_line_number, "".join(new_line)
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:90B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:89     ) -> None:
90         assert req is None or isinstance(req, Requirement), req
91         self.req = req
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:104B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:103         if self.editable:
104             assert link
105             if link.is_file:
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:252B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:251             return False
252         assert self.pep517_backend
253         with self.build_env:
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:262B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:261     def specifier(self) -> SpecifierSet:
262         assert self.req is not None
263         return self.req.specifier
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:276B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:275         """
276         assert self.req is not None
277         specifiers = self.req.specifier
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:325B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:324         if link and link.hash:
325             assert link.hash_name is not None
326             good_hashes.setdefault(link.hash_name, []).append(link.hash)
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:347B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:346     ) -> str:
347         assert build_dir is not None
348         if self._temp_build_dir is not None:
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:349B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:348         if self._temp_build_dir is not None:
349             assert self._temp_build_dir.path
350             return self._temp_build_dir.path
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:389B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:388         """Set requirement after generating metadata."""
389         assert self.req is None
390         assert self.metadata is not None
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:390B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:389         assert self.req is None
390         assert self.metadata is not None
391         assert self.source_dir is not None
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:391B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:390         assert self.metadata is not None
391         assert self.source_dir is not None
392 
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:410B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:409     def warn_on_mismatching_name(self) -> None:
410         assert self.req is not None
411         metadata_name = canonicalize_name(self.metadata["Name"])
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:480B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:479     def unpacked_source_directory(self) -> str:
480         assert self.source_dir, f"No source dir for {self}"
481         return os.path.join(
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:487B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:486     def setup_py_path(self) -> str:
487         assert self.source_dir, f"No source dir for {self}"
488         setup_py = os.path.join(self.unpacked_source_directory, "setup.py")
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:494B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:493     def setup_cfg_path(self) -> str:
494         assert self.source_dir, f"No source dir for {self}"
495         setup_cfg = os.path.join(self.unpacked_source_directory, "setup.cfg")
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:501B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:500     def pyproject_toml_path(self) -> str:
501         assert self.source_dir, f"No source dir for {self}"
502         return make_pyproject_path(self.unpacked_source_directory)
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:517B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:516         if pyproject_toml_data is None:
517             assert not self.config_settings
518             self.use_pep517 = False
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:559B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:558         """
559         assert self.source_dir, f"No source dir for {self}"
560         details = self.name or f"from {self.link}"
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:563B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:562         if self.use_pep517:
563             assert self.pep517_backend is not None
564             if (
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:608B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:607         elif self.local_file_path and self.is_wheel:
608             assert self.req is not None
609             return get_wheel_distribution(
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:619B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:618     def assert_source_matches_version(self) -> None:
619         assert self.source_dir, f"No source dir for {self}"
620         version = self.metadata["version"]
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:659B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:658     def needs_unpacked_archive(self, archive_source: Path) -> None:
659         assert self._archive_source is None
660         self._archive_source = archive_source
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:664B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:663         """Ensure the source directory has not yet been built in."""
664         assert self.source_dir is not None
665         if self._archive_source is not None:
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:687B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:686             return
687         assert self.editable
688         assert self.source_dir
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:688B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:687         assert self.editable
688         assert self.source_dir
689         if self.link.scheme == "file":
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:695B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:694         # So here, if it's neither a path nor a valid VCS URL, it's a bug.
695         assert vcs_backend, f"Unsupported VCS URL {self.link.url}"
696         hidden_url = hide_url(self.link.url)
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:715B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:714         """
715         assert self.req
716         dist = get_default_environment().get_distribution(self.req.name)
Bunknownb j��
V./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:728-729-730B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:727         def _clean_zip_name(name: str, prefix: str) -> str:
728             assert name.startswith(
729                 prefix + os.path.sep
730             ), f"name {name!r} doesn't start with prefix {prefix!r}"
731             name = name[len(prefix) + 1 :]
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:735B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:734 
735         assert self.req is not None
736         path = os.path.join(parentdir, path)
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:745B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:744         """
745         assert self.source_dir
746         if build_dir is None:
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:817B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:816     ) -> None:
817         assert self.req is not None
818         scheme = get_scheme(
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:864B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:863 
864         assert self.is_wheel
865         assert self.local_file_path
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_install.py:865B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:864         assert self.is_wheel
865         assert self.local_file_path
866 
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_set.py:42B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:41     def add_unnamed_requirement(self, install_req: InstallRequirement) -> None:
42         assert not install_req.name
43         self.unnamed_requirements.append(install_req)
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_set.py:46B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:45     def add_named_requirement(self, install_req: InstallRequirement) -> None:
46         assert install_req.name
47 
Bunknownb j��
O./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_uninstall.py:70B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:69     location = dist.location
70     assert location is not None, "not installed"
71 
Bunknownb j��
d./bandit-env/lib/python3.12/site-packages/pip/_internal/req/req_uninstall.py:528-529-530-531-532-533B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:527                 )
528             assert os.path.samefile(
529                 normalized_link_pointer, normalized_dist_location
530             ), (
531                 f"Egg-link {develop_egg_link} (to {link_pointer}) does not match "
532                 f"installed location of {dist.raw_name} (at {dist_location})"
533             )
534             paths_to_remove.add(develop_egg_link)
Bunknownb j��
Y./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/legacy/resolver.py:131B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:130         super().__init__()
131         assert upgrade_strategy in self._allowed_strategies
132 
Bunknownb j��
a./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/legacy/resolver.py:234-235-236B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:233         # This next bit is really a sanity check.
234         assert (
235             not install_req.user_supplied or parent_req_name is None
236         ), "a user supplied req shouldn't have a parent"
237 
Bunknownb j��
Y./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/legacy/resolver.py:312B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:311         else:
312             assert self.upgrade_strategy == "only-if-needed"
313             return req.user_supplied or req.constraint
Bunknownb j��
Y./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/legacy/resolver.py:321B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:320         # conflict is not a user install.
321         assert req.satisfied_by is not None
322         if not self.use_user_site or req.satisfied_by.in_usersite:
Bunknownb j��
Y./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/legacy/resolver.py:421B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:420 
421         assert req.link is not None, "_find_requirement_link unexpectedly returned None"
422         cache_entry = self.wheel_cache.get_cache_entry(
Bunknownb j��
Y./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/legacy/resolver.py:450B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:449         # so it must be None here.
450         assert req.satisfied_by is None
451         skip_reason = self._check_skip_installed(req)
Bunknownb j��
Y./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/legacy/resolver.py:535B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:534             # can refer to it when adding dependencies.
535             assert req_to_install.name is not None
536             if not requirement_set.has_requirement(req_to_install.name):
Bunknownb j��
Y./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/legacy/resolver.py:540B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:539                 # provided by the user.
540                 assert req_to_install.user_supplied
541                 self._add_requirement_to_set(
Bunknownb j��
^./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/resolvelib/candidates.py:58B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:57 ) -> InstallRequirement:
58     assert not template.editable, "template is editable"
59     if template.req:
Bunknownb j��
^./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/resolvelib/candidates.py:83B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:82 ) -> InstallRequirement:
83     assert template.editable, "template not editable"
84     ireq = install_req_from_editable(
Bunknownb j��
_./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/resolvelib/candidates.py:277B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:276         ireq = make_install_req_from_link(link, template)
277         assert ireq.link == link
278         if ireq.link.is_wheel and not ireq.link.is_file:
Bunknownb j��
_./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/resolvelib/candidates.py:281B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:280             wheel_name = canonicalize_name(wheel.name)
281             assert name == wheel_name, f"{name!r} != {wheel_name!r} for wheel"
282             # Version may not be present for PEP 508 direct URLs
Bunknownb j��
g./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/resolvelib/candidates.py:285-286-287B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:284                 wheel_version = Version(wheel.version)
285                 assert (
286                     version == wheel_version
287                 ), f"{version!r} != {wheel_version!r} for wheel {name}"
288 
Bunknownb j��
_./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/resolvelib/candidates.py:290B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:289         if cache_entry is not None:
290             assert ireq.link.is_wheel
291             assert ireq.link.is_file
Bunknownb j��
_./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/resolvelib/candidates.py:291B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:290             assert ireq.link.is_wheel
291             assert ireq.link.is_file
292             if cache_entry.persistent and template.link is template.original_link:
Bunknownb j��
\./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/resolvelib/factory.py:266B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:265         template = ireqs[0]
266         assert template.req, "Candidates found on index must be PEP 508"
267         name = canonicalize_name(template.req.name)
Bunknownb j��
\./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/resolvelib/factory.py:271B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:270         for ireq in ireqs:
271             assert ireq.req, "Candidates found on index must be PEP 508"
272             specifier &= ireq.req.specifier
Bunknownb j��
\./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/resolvelib/factory.py:366B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:365             base_cand = as_base_candidate(lookup_cand)
366             assert base_cand is not None, "no extras here"
367             yield self._make_extras_candidate(base_cand, extras)
Bunknownb j��
\./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/resolvelib/factory.py:532B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:531                     continue
532                 assert ireq.name, "Constraint must be named"
533                 name = canonicalize_name(ireq.name)
Bunknownb j��
\./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/resolvelib/factory.py:646B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:645     ) -> UnsupportedPythonVersion:
646         assert causes, "Requires-Python error reported with no cause"
647 
Bunknownb j��
\./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/resolvelib/factory.py:722B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:721     ) -> InstallationError:
722         assert e.causes, "Installation error reported with no cause"
723 
Bunknownb j��
`./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/resolvelib/requirements.py:52B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:51     def __init__(self, ireq: InstallRequirement) -> None:
52         assert ireq.link is None, "This is a link, not a specifier"
53         self._ireq = ireq
Bunknownb j��
`./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/resolvelib/requirements.py:86B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:85     def project_name(self) -> NormalizedName:
86         assert self._ireq.req, "Specifier-backed ireq is always PEP 508"
87         return canonicalize_name(self._ireq.req.name)
Bunknownb j��
m./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/resolvelib/requirements.py:110-111-112-113B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:109     def is_satisfied_by(self, candidate: Candidate) -> bool:
110         assert candidate.name == self.name, (
111             f"Internal issue: Candidate is not for this requirement "
112             f"{candidate.name} vs {self.name}"
113         )
114         # We can safely always allow prereleases here since PackageFinder
Bunknownb j��
a./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/resolvelib/requirements.py:117B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:116         # prerelease candidates if the user does not expect them.
117         assert self._ireq.req, "Specifier-backed ireq is always PEP 508"
118         spec = self._ireq.req.specifier
Bunknownb j��
a./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/resolvelib/requirements.py:129B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:128     def __init__(self, ireq: InstallRequirement) -> None:
129         assert ireq.link is None, "This is a link, not a specifier"
130         self._ireq = install_req_drop_extras(ireq)
Bunknownb j��
a./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/resolvelib/requirements.py:203B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:202     def is_satisfied_by(self, candidate: Candidate) -> bool:
203         assert candidate.name == self._candidate.name, "Not Python candidate"
204         # We can safely always allow prereleases here since PackageFinder
Bunknownb j��
\./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/resolvelib/resolver.py:56B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:55         super().__init__()
56         assert upgrade_strategy in self._allowed_strategies
57 
Bunknownb j��
]./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/resolvelib/resolver.py:200B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:199         """
200         assert self._result is not None, "must call resolve() first"
201 
Bunknownb j��
]./bandit-env/lib/python3.12/site-packages/pip/_internal/resolution/resolvelib/resolver.py:301B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:300     difference = set(weights.keys()).difference(requirement_keys)
301     assert not difference, difference
302 
Bunknownb j��
V./bandit-env/lib/python3.12/site-packages/pip/_internal/utils/direct_url_helpers.py:23B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:22     else:
23         assert isinstance(direct_url.info, DirInfo)
24         requirement += direct_url.url
Bunknownb j��
V./bandit-env/lib/python3.12/site-packages/pip/_internal/utils/direct_url_helpers.py:44B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:43         vcs_backend = vcs.get_backend_for_scheme(link.scheme)
44         assert vcs_backend
45         url, requested_revision, _ = vcs_backend.get_url_rev_and_auth(
Bunknownb j��
V./bandit-env/lib/python3.12/site-packages/pip/_internal/utils/direct_url_helpers.py:55B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:54             # with the VCS checkout.
55             assert requested_revision
56             commit_id = requested_revision
Bunknownb j��
V./bandit-env/lib/python3.12/site-packages/pip/_internal/utils/direct_url_helpers.py:61B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:60             # which we can inspect to find out the commit id.
61             assert source_dir
62             commit_id = vcs_backend.get_revision(source_dir)
Bunknownb j��
L./bandit-env/lib/python3.12/site-packages/pip/_internal/utils/encoding.py:31B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:30             result = ENCODING_RE.search(line)
31             assert result is not None
32             encoding = result.groups()[0].decode("ascii")
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/utils/filesystem.py:21B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:20 
21     assert os.path.isabs(path)
22 
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/utils/filesystem.py:96B311	blacklist 0:�Standard pseudo-random generators are not suitable for security/cryptographic purposes.
code:95     for _ in range(10):
96         name = basename + "".join(random.choice(alphabet) for _ in range(6))
97         file = os.path.join(path, name)
Bunknownb j��
L./bandit-env/lib/python3.12/site-packages/pip/_internal/utils/logging.py:158B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:157         if getattr(record, "rich", False):
158             assert isinstance(record.args, tuple)
159             (rich_renderable,) = record.args
Bunknownb j��
T./bandit-env/lib/python3.12/site-packages/pip/_internal/utils/logging.py:160-161-162B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:159             (rich_renderable,) = record.args
160             assert isinstance(
161                 rich_renderable, (ConsoleRenderable, RichCast, str)
162             ), f"{rich_renderable} is not rich-console-renderable"
163 
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pip/_internal/utils/misc.py:479B105hardcoded_password_string 0:gPossible hardcoded password: ''
code:478         user = "****"
479         password = ""
480     else:
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pip/_internal/utils/misc.py:482B105hardcoded_password_string 0:�Possible hardcoded password: ':****'
code:481         user = urllib.parse.quote(user)
482         password = ":****"
483     return f"{user}{password}@{netloc}"
Bunknownb j��
U./bandit-env/lib/python3.12/site-packages/pip/_internal/utils/setuptools_build.py:113B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:112 ) -> List[str]:
113     assert not (use_user_site and prefix)
114 
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pip/_internal/utils/subprocess.py:4B404	blacklist 0:�Consider possible security implications associated with the subprocess module.
code:3 import shlex
4 import subprocess
5 from typing import Any, Callable, Iterable, List, Literal, Mapping, Optional, Union
Bunknownb jN�
s./bandit-env/lib/python3.12/site-packages/pip/_internal/utils/subprocess.py:126-127-128-129-130-131-132-133-134-135B603$subprocess_without_shell_equals_true 0:�subprocess call - check for execution of untrusted input.
code:125     try:
126         proc = subprocess.Popen(
127             # Convert HiddenText objects to the underlying str.
128             reveal_command_args(cmd),
129             stdin=subprocess.PIPE,
130             stdout=subprocess.PIPE,
131             stderr=subprocess.STDOUT if not stdout_only else subprocess.PIPE,
132             cwd=cwd,
133             env=env,
134             errors="backslashreplace",
135         )
136     except Exception as exc:
Bunknownb jN�
O./bandit-env/lib/python3.12/site-packages/pip/_internal/utils/subprocess.py:146B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:145     if not stdout_only:
146         assert proc.stdout
147         assert proc.stdin
Bunknownb j��
O./bandit-env/lib/python3.12/site-packages/pip/_internal/utils/subprocess.py:147B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:146         assert proc.stdout
147         assert proc.stdin
148         proc.stdin.close()
Bunknownb j��
O./bandit-env/lib/python3.12/site-packages/pip/_internal/utils/subprocess.py:161B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:160             if use_spinner:
161                 assert spinner
162                 spinner.spin()
Bunknownb j��
O./bandit-env/lib/python3.12/site-packages/pip/_internal/utils/subprocess.py:184B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:183     if use_spinner:
184         assert spinner
185         if proc_had_error:
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pip/_internal/utils/temp_dir.py:146B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:145         if globally_managed:
146             assert _tempdir_manager is not None
147             _tempdir_manager.enter_context(self)
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pip/_internal/utils/temp_dir.py:151B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:150     def path(self) -> str:
151         assert not self._deleted, f"Attempted to access deleted path: {self._path}"
152         return self._path
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/utils/unpacking.py:245B202tarfile_unsafe_members 0:�tarfile.extractall used without any validation. Please check and discard dangerous members.
code:244 
245             tar.extractall(location, filter=pip_filter)
246 
Bunknownb j�
N./bandit-env/lib/python3.12/site-packages/pip/_internal/utils/unpacking.py:298B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:297             ensure_dir(os.path.dirname(path))
298             assert fp is not None
299             with open(path, "wb") as destfp:
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_internal/utils/urls.py:23-24-25B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:22     """
23     assert url.startswith(
24         "file:"
25     ), f"You can only turn file: urls into filenames (not {url!r})"
26 
Bunknownb j��
F./bandit-env/lib/python3.12/site-packages/pip/_internal/vcs/git.py:215B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:214         # rev return value is always non-None.
215         assert rev is not None
216 
Bunknownb j��
F./bandit-env/lib/python3.12/site-packages/pip/_internal/vcs/git.py:478B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:477         if "://" not in url:
478             assert "file:" not in url
479             url = url.replace("git+", "git+ssh://")
Bunknownb j��
L./bandit-env/lib/python3.12/site-packages/pip/_internal/vcs/subversion.py:65B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:64             if base == location:
65                 assert dirurl is not None
66                 base = dirurl + "/"  # save the root url
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pip/_internal/vcs/subversion.py:169B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:168                 match = _svn_info_xml_url_re.search(xml)
169                 assert match is not None
170                 url = match.group(1)
Bunknownb j��
L./bandit-env/lib/python3.12/site-packages/pip/_internal/wheel_builder.py:105B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:104         # unless it points to an immutable commit hash.
105         assert not req.editable
106         assert req.source_dir
Bunknownb j��
L./bandit-env/lib/python3.12/site-packages/pip/_internal/wheel_builder.py:106B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:105         assert not req.editable
106         assert req.source_dir
107         vcs_backend = vcs.get_backend_for_scheme(req.link.scheme)
Bunknownb j��
L./bandit-env/lib/python3.12/site-packages/pip/_internal/wheel_builder.py:108B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:107         vcs_backend = vcs.get_backend_for_scheme(req.link.scheme)
108         assert vcs_backend
109         if vcs_backend.is_immutable_rev_checkout(req.link.url, req.source_dir):
Bunknownb j��
L./bandit-env/lib/python3.12/site-packages/pip/_internal/wheel_builder.py:113B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:112 
113     assert req.link
114     base, ext = req.link.splitext()
Bunknownb j��
L./bandit-env/lib/python3.12/site-packages/pip/_internal/wheel_builder.py:130B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:129     cache_available = bool(wheel_cache.cache_dir)
130     assert req.link
131     if cache_available and _should_cache(req):
Bunknownb j��
L./bandit-env/lib/python3.12/site-packages/pip/_internal/wheel_builder.py:213B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:212     with TempDirectory(kind="wheel") as temp_dir:
213         assert req.name
214         if req.use_pep517:
Bunknownb j��
L./bandit-env/lib/python3.12/site-packages/pip/_internal/wheel_builder.py:215B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:214         if req.use_pep517:
215             assert req.metadata_directory
216             assert req.pep517_backend
Bunknownb j��
L./bandit-env/lib/python3.12/site-packages/pip/_internal/wheel_builder.py:216B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:215             assert req.metadata_directory
216             assert req.pep517_backend
217             if global_options:
Bunknownb j��
L./bandit-env/lib/python3.12/site-packages/pip/_internal/wheel_builder.py:317B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:316         for req in requirements:
317             assert req.name
318             cache_dir = _get_cache_dir(req, wheel_cache)
Bunknownb j��
L./bandit-env/lib/python3.12/site-packages/pip/_internal/wheel_builder.py:337B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:336                 req.local_file_path = req.link.file_path
337                 assert req.link.is_wheel
338                 build_successes.append(req)
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_vendor/cachecontrol/adapter.py:150B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:149         if request.method in self.invalidating_methods and resp.ok:
150             assert request.url is not None
151             cache_url = self.controller.cache_url(request.url)
Bunknownb j��
S./bandit-env/lib/python3.12/site-packages/pip/_vendor/cachecontrol/controller.py:43B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:42     match = URI.match(uri)
43     assert match is not None
44     groups = match.groups()
Bunknownb j��
T./bandit-env/lib/python3.12/site-packages/pip/_vendor/cachecontrol/controller.py:151B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:150         cache_url = request.url
151         assert cache_url is not None
152         cache_data = self.cache.get(cache_url)
Bunknownb j��
T./bandit-env/lib/python3.12/site-packages/pip/_vendor/cachecontrol/controller.py:172B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:171         """
172         assert request.url is not None
173         cache_url = self.cache_url(request.url)
Bunknownb j��
T./bandit-env/lib/python3.12/site-packages/pip/_vendor/cachecontrol/controller.py:220B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:219         time_tuple = parsedate_tz(headers["date"])
220         assert time_tuple is not None
221         date = calendar.timegm(time_tuple[:6])
Bunknownb j��
T./bandit-env/lib/python3.12/site-packages/pip/_vendor/cachecontrol/controller.py:349B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:348             time_tuple = parsedate_tz(response_headers["date"])
349             assert time_tuple is not None
350             date = calendar.timegm(time_tuple[:6])
Bunknownb j��
T./bandit-env/lib/python3.12/site-packages/pip/_vendor/cachecontrol/controller.py:369B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:368 
369         assert request.url is not None
370         cache_url = self.cache_url(request.url)
Bunknownb j��
T./bandit-env/lib/python3.12/site-packages/pip/_vendor/cachecontrol/controller.py:421B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:420             time_tuple = parsedate_tz(response_headers["date"])
421             assert time_tuple is not None
422             date = calendar.timegm(time_tuple[:6])
Bunknownb j��
T./bandit-env/lib/python3.12/site-packages/pip/_vendor/cachecontrol/controller.py:468B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:467         """
468         assert request.url is not None
469         cache_url = self.cache_url(request.url)
Bunknownb j��
T./bandit-env/lib/python3.12/site-packages/pip/_vendor/cachecontrol/heuristics.py:137B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:136         time_tuple = parsedate_tz(headers["date"])
137         assert time_tuple is not None
138         date = calendar.timegm(time_tuple[:6])
Bunknownb j��
J./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/compat.py:42B411	blacklist 0:�Using xmlrpclib to parse untrusted XML data is known to be vulnerable to XML attacks. Use defusedxml.xmlrpc.monkey_patch() function to monkey-patch xmlrpclib and mitigate XML vulnerabilities.
code:41     import httplib
42     import xmlrpclib
43     import Queue as queue
Bunknownb j�
J./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/compat.py:81B411	blacklist 0:�Using xmlrpc.client to parse untrusted XML data is known to be vulnerable to XML attacks. Use defusedxml.xmlrpc.monkey_patch() function to monkey-patch xmlrpclib and mitigate XML vulnerabilities.
code:80     import urllib.request as urllib2
81     import xmlrpc.client as xmlrpclib
82     import queue
Bunknownb j�
K./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/compat.py:634B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:633     def cache_from_source(path, debug_override=None):
634         assert path.endswith('.py')
635         if debug_override is None:
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/database.py:1032B324hashlib 0:�Use of weak MD5 hash for security. Consider usedforsecurity=False
code:1031                 f.close()
1032             return hashlib.md5(content).hexdigest()
1033 
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/index.py:11B404	blacklist 0:�Consider possible security implications associated with the subprocess module.
code:10 import shutil
11 import subprocess
12 import tempfile
Bunknownb jN�
L./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/index.py:58-59B603$subprocess_without_shell_equals_true 0:�subprocess call - check for execution of untrusted input.
code:57                 try:
58                     rc = subprocess.check_call([s, '--version'], stdout=sink,
59                                                stderr=sink)
60                     if rc == 0:
Bunknownb jN�
J./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/index.py:193B603$subprocess_without_shell_equals_true 0:�subprocess call - check for execution of untrusted input.
code:192         stderr = []
193         p = subprocess.Popen(cmd, **kwargs)
194         # We don't use communicate() here because we may need to
Bunknownb jN�
J./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/index.py:269B324hashlib 0:�Use of weak MD5 hash for security. Consider usedforsecurity=False
code:268             file_data = f.read()
269         md5_digest = hashlib.md5(file_data).hexdigest()
270         sha256_digest = hashlib.sha256(file_data).hexdigest()
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/locators.py:953B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:952         super(DistPathLocator, self).__init__(**kwargs)
953         assert isinstance(distpath, DistributionPath)
954         self.distpath = distpath
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/manifest.py:115B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:114                 parent, _ = os.path.split(d)
115                 assert parent not in ('', '/')
116                 add_dir(dirs, parent)
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/manifest.py:330B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:329             if _PYTHON_VERSION > (3, 2):
330                 assert pattern_re.startswith(start) and pattern_re.endswith(end)
331         else:
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/manifest.py:342B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:341                 prefix_re = self._glob_to_re(prefix)
342                 assert prefix_re.startswith(start) and prefix_re.endswith(end)
343                 prefix_re = prefix_re[len(start): len(prefix_re) - len(end)]
Bunknownb j��
K./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/markers.py:78B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:77         else:
78             assert isinstance(expr, dict)
79             op = expr['op']
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/metadata.py:930B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:929     def _from_legacy(self):
930         assert self._legacy and not self._data
931         result = {
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/metadata.py:993B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:992 
993         assert self._data and not self._legacy
994         result = LegacyMetadata()
Bunknownb j��
P./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/scripts.py:315-316B110try_except_pass 0:�Try, Except, Pass detected.
code:314                         os.remove(dfname)
315                     except Exception:
316                         pass  # still in use - ignore error
317             else:
Bunknownb j��
H./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/util.py:21B404	blacklist 0:�Consider possible security implications associated with the subprocess module.
code:20     ssl = None
21 import subprocess
22 import sys
Bunknownb jN�
I./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/util.py:287B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:286         path = path.replace(os.path.sep, '/')
287         assert path.startswith(root)
288         return path[len(root):].lstrip('/')
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/util.py:374B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:373                 entry = get_export_entry(s)
374                 assert entry is not None
375                 entries[k] = entry
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/util.py:401B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:400             entry = get_export_entry(s)
401             assert entry is not None
402             # entry.dist = self
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/util.py:552B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:551     def copy_stream(self, instream, outfile, encoding=None):
552         assert not os.path.isdir(outfile)
553         self.ensure_dir(os.path.dirname(outfile))
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/util.py:617B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:616                 else:
617                     assert path.startswith(prefix)
618                     diagpath = path[len(prefix):]
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/util.py:667B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:666         """
667         assert self.record
668         result = self.files_written, self.dirs_created
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/util.py:684B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:683                 if flist:
684                     assert flist == ['__pycache__']
685                     sd = os.path.join(d, flist[0])
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/util.py:864B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:863             break
864     assert i is not None
865     return result
Bunknownb j��
J./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/util.py:1130B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:1129     def add(self, pred, succ):
1130         assert pred != succ
1131         self._preds.setdefault(succ, set()).add(pred)
Bunknownb j��
J./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/util.py:1135B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:1134     def remove(self, pred, succ):
1135         assert pred != succ
1136         try:
Bunknownb j��
J./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/util.py:1310B202tarfile_unsafe_members 0:�tarfile.extractall used without any validation. Please check and discard dangerous members.
code:1309 
1310         archive.extractall(dest_dir)
1311 
Bunknownb j�
J./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/util.py:1342B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:1341     def __init__(self, minval=0, maxval=100):
1342         assert maxval is None or maxval >= minval
1343         self.min = self.cur = minval
Bunknownb j��
J./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/util.py:1350B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:1349     def update(self, curval):
1350         assert self.min <= curval
1351         assert self.max is None or curval <= self.max
Bunknownb j��
J./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/util.py:1351B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:1350         assert self.min <= curval
1351         assert self.max is None or curval <= self.max
1352         self.cur = curval
Bunknownb j��
J./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/util.py:1360B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:1359     def increment(self, incr):
1360         assert incr >= 0
1361         self.update(self.cur + incr)
Bunknownb j��
J./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/util.py:1451B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:1450     if len(rich_path_glob) > 1:
1451         assert len(rich_path_glob) == 3, rich_path_glob
1452         prefix, set, suffix = rich_path_glob
Bunknownb j��
Y./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/util.py:1792-1793-1794-1795B603$subprocess_without_shell_equals_true 0:�subprocess call - check for execution of untrusted input.
code:1791     def run_command(self, cmd, **kwargs):
1792         p = subprocess.Popen(cmd,
1793                              stdout=subprocess.PIPE,
1794                              stderr=subprocess.PIPE,
1795                              **kwargs)
1796         t1 = threading.Thread(target=self.reader, args=(p.stdout, 'stdout'))
Bunknownb jN�
K./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/version.py:34B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:33         self._parts = parts = self.parse(s)
34         assert isinstance(parts, tuple)
35         assert len(parts) > 0
Bunknownb j��
K./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/version.py:35B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:34         assert isinstance(parts, tuple)
35         assert len(parts) > 0
36 
Bunknownb j��
J./bandit-env/lib/python3.12/site-packages/pip/_vendor/distlib/wheel.py:437B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:436                         break
437                 assert distinfo, '.dist-info directory expected, not found'
438 
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pip/_vendor/distro/distro.py:37B404	blacklist 0:�Consider possible security implications associated with the subprocess module.
code:36 import shlex
37 import subprocess
38 import sys
Bunknownb jN�
J./bandit-env/lib/python3.12/site-packages/pip/_vendor/distro/distro.py:644B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:643         def __get__(self, obj: Any, owner: Type[Any]) -> Any:
644             assert obj is not None, f"call {self._fname} on an instance"
645             ret = obj.__dict__[self._fname] = self._f(obj)
Bunknownb j��
K./bandit-env/lib/python3.12/site-packages/pip/_vendor/distro/distro.py:1165B603$subprocess_without_shell_equals_true 0:�subprocess call - check for execution of untrusted input.
code:1164             cmd = ("lsb_release", "-a")
1165             stdout = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
1166         # Command not found or lsb_release returned error
Bunknownb jN�
K./bandit-env/lib/python3.12/site-packages/pip/_vendor/distro/distro.py:1202B603$subprocess_without_shell_equals_true 0:�subprocess call - check for execution of untrusted input.
code:1201             cmd = ("uname", "-rs")
1202             stdout = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
1203         except OSError:
Bunknownb jN�
K./bandit-env/lib/python3.12/site-packages/pip/_vendor/distro/distro.py:1213B607start_process_with_partial_path 0:�Starting a process with a partial executable path
code:1212         try:
1213             stdout = subprocess.check_output("oslevel", stderr=subprocess.DEVNULL)
1214         except (OSError, subprocess.CalledProcessError):
Bunknownb jN�
K./bandit-env/lib/python3.12/site-packages/pip/_vendor/distro/distro.py:1213B603$subprocess_without_shell_equals_true 0:�subprocess call - check for execution of untrusted input.
code:1212         try:
1213             stdout = subprocess.check_output("oslevel", stderr=subprocess.DEVNULL)
1214         except (OSError, subprocess.CalledProcessError):
Bunknownb jN�
M./bandit-env/lib/python3.12/site-packages/pip/_vendor/msgpack/fallback.py:323B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:322     def feed(self, next_bytes):
323         assert self._feeding
324         view = _get_data_from_buffer(next_bytes)
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pip/_vendor/msgpack/fallback.py:387B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:386                 break
387             assert isinstance(read_data, bytes)
388             self._buffer += read_data
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pip/_vendor/msgpack/fallback.py:562B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:561                 return self._ext_hook(n, bytes(obj))
562         assert typ == TYPE_IMMEDIATE
563         return obj
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pip/_vendor/msgpack/fallback.py:776B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:775                     data = obj.data
776                 assert isinstance(code, int)
777                 assert isinstance(data, bytes)
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pip/_vendor/msgpack/fallback.py:777B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:776                 assert isinstance(code, int)
777                 assert isinstance(data, bytes)
778                 L = len(data)
Bunknownb j��
P./bandit-env/lib/python3.12/site-packages/pip/_vendor/packaging/_manylinux.py:96B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:95         version_string: str | None = os.confstr("CS_GNU_LIBC_VERSION")
96         assert version_string is not None
97         _, version = version_string.rsplit()
Bunknownb j��
P./bandit-env/lib/python3.12/site-packages/pip/_vendor/packaging/_musllinux.py:11B404	blacklist 0:�Consider possible security implications associated with the subprocess module.
code:10 import re
11 import subprocess
12 import sys
Bunknownb jN�
P./bandit-env/lib/python3.12/site-packages/pip/_vendor/packaging/_musllinux.py:52B603$subprocess_without_shell_equals_true 0:�subprocess call - check for execution of untrusted input.
code:51         return None
52     proc = subprocess.run([ld], stderr=subprocess.PIPE, text=True)
53     return _parse_musl_version(proc.stderr)
Bunknownb jN�
P./bandit-env/lib/python3.12/site-packages/pip/_vendor/packaging/_musllinux.py:79B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:78     plat = sysconfig.get_platform()
79     assert plat.startswith("linux-"), "not linux"
80 
Bunknownb j��
Y./bandit-env/lib/python3.12/site-packages/pip/_vendor/packaging/_tokenizer.py:122-123-124B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:121         """
122         assert (
123             self.next_token is None
124         ), f"Cannot check for {name!r}, already have {self.next_token!r}"
125         assert name in self.rules, f"Unknown token name: {name!r}"
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_vendor/packaging/_tokenizer.py:125B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:124         ), f"Cannot check for {name!r}, already have {self.next_token!r}"
125         assert name in self.rules, f"Unknown token name: {name!r}"
126 
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_vendor/packaging/_tokenizer.py:148B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:147         token = self.next_token
148         assert token is not None
149 
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_vendor/packaging/markers.py:140B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:139 ) -> str:
140     assert isinstance(marker, (list, tuple, str))
141 
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_vendor/packaging/markers.py:208B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:207     for marker in markers:
208         assert isinstance(marker, (list, tuple, str))
209 
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_vendor/packaging/markers.py:227B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:226         else:
227             assert marker in ["and", "or"]
228             if marker == "or":
Bunknownb j��
O./bandit-env/lib/python3.12/site-packages/pip/_vendor/packaging/metadata.py:327B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:326             # a str, so we'll just assert here to make sure.
327             assert isinstance(h, (email.header.Header, str))
328 
Bunknownb j��
J./bandit-env/lib/python3.12/site-packages/pip/_vendor/packaging/tags.py:11B404	blacklist 0:�Consider possible security implications associated with the subprocess module.
code:10 import struct
11 import subprocess
12 import sys
Bunknownb jN�
w./bandit-env/lib/python3.12/site-packages/pip/_vendor/packaging/tags.py:415-416-417-418-419-420-421-422-423-424-425-426B603$subprocess_without_shell_equals_true 0:�subprocess call - check for execution of untrusted input.
code:414             # instead of the real version.
415             version_str = subprocess.run(
416                 [
417                     sys.executable,
418                     "-sS",
419                     "-c",
420                     "import platform; print(platform.mac_ver()[0])",
421                 ],
422                 check=True,
423                 env={"SYSTEM_VERSION_COMPAT": "0"},
424                 stdout=subprocess.PIPE,
425                 text=True,
426             ).stdout
427             version = cast("MacVersion", tuple(map(int, version_str.split(".")[:2])))
Bunknownb jN�
T./bandit-env/lib/python3.12/site-packages/pip/_vendor/pkg_resources/__init__.py:1714B102	exec_used 0:�Use of exec detected.
code:1713             code = compile(source, script_filename, 'exec')
1714             exec(code, namespace, namespace)
1715         else:
Bunknownb jN�
T./bandit-env/lib/python3.12/site-packages/pip/_vendor/pkg_resources/__init__.py:1725B102	exec_used 0:�Use of exec detected.
code:1724             script_code = compile(script_text, script_filename, 'exec')
1725             exec(script_code, namespace, namespace)
1726 
Bunknownb jN�
N./bandit-env/lib/python3.12/site-packages/pip/_vendor/platformdirs/unix.py:179B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:178                 if not Path(path).exists():
179                     path = f"/tmp/runtime-{getuid()}"  # noqa: S108
180             else:
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_vendor/pygments/cmdline.py:522-523B110try_except_pass 0:�Try, Except, Pass detected.
code:521                 width = shutil.get_terminal_size().columns - 2
522             except Exception:
523                 pass
524         argparse.HelpFormatter.__init__(self, prog, indent_increment,
Bunknownb j��
Y./bandit-env/lib/python3.12/site-packages/pip/_vendor/pygments/formatters/__init__.py:103B102	exec_used 0:�Use of exec detected.
code:102         with open(filename, 'rb') as f:
103             exec(f.read(), custom_namespace)
104         # Retrieve the class `formattername` from that namespace
Bunknownb jN�
S./bandit-env/lib/python3.12/site-packages/pip/_vendor/pygments/formatters/img.py:17B404	blacklist 0:qConsider possible security implications associated with the subprocess module.
code:16 
17 import subprocess
18 
Bunknownb jN�
V./bandit-env/lib/python3.12/site-packages/pip/_vendor/pygments/formatters/img.py:93-94B607start_process_with_partial_path 0:�Starting a process with a partial executable path
code:92     def _get_nix_font_path(self, name, style):
93         proc = subprocess.Popen(['fc-list', f"{name}:style={style}", 'file'],
94                                 stdout=subprocess.PIPE, stderr=None)
95         stdout, _ = proc.communicate()
Bunknownb jN�
V./bandit-env/lib/python3.12/site-packages/pip/_vendor/pygments/formatters/img.py:93-94B603$subprocess_without_shell_equals_true 0:�subprocess call - check for execution of untrusted input.
code:92     def _get_nix_font_path(self, name, style):
93         proc = subprocess.Popen(['fc-list', f"{name}:style={style}", 'file'],
94                                 stdout=subprocess.PIPE, stderr=None)
95         stdout, _ = proc.communicate()
Bunknownb jN�
O./bandit-env/lib/python3.12/site-packages/pip/_vendor/pygments/lexer.py:514-515B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:513         """Preprocess the token component of a token definition."""
514         assert type(token) is _TokenType or callable(token), \
515             f'token type must be simple type or callable, not {token!r}'
516         return token
Bunknownb j��
K./bandit-env/lib/python3.12/site-packages/pip/_vendor/pygments/lexer.py:531B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:530             else:
531                 assert False, f'unknown new state {new_state!r}'
532         elif isinstance(new_state, combined):
Bunknownb j��
K./bandit-env/lib/python3.12/site-packages/pip/_vendor/pygments/lexer.py:538B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:537             for istate in new_state:
538                 assert istate != new_state, f'circular state ref {istate!r}'
539                 itokens.extend(cls._process_state(unprocessed,
Bunknownb j��
S./bandit-env/lib/python3.12/site-packages/pip/_vendor/pygments/lexer.py:546-547-548B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:545             for istate in new_state:
546                 assert (istate in unprocessed or
547                         istate in ('#pop', '#push')), \
548                     'unknown new state ' + istate
549             return new_state
Bunknownb j��
K./bandit-env/lib/python3.12/site-packages/pip/_vendor/pygments/lexer.py:551B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:550         else:
551             assert False, f'unknown new state def {new_state!r}'
552 
Bunknownb j��
K./bandit-env/lib/python3.12/site-packages/pip/_vendor/pygments/lexer.py:555B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:554         """Preprocess a single state definition."""
555         assert isinstance(state, str), f"wrong state name {state!r}"
556         assert state[0] != '#', f"invalid state name {state!r}"
Bunknownb j��
K./bandit-env/lib/python3.12/site-packages/pip/_vendor/pygments/lexer.py:556B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:555         assert isinstance(state, str), f"wrong state name {state!r}"
556         assert state[0] != '#', f"invalid state name {state!r}"
557         if state in processed:
Bunknownb j��
K./bandit-env/lib/python3.12/site-packages/pip/_vendor/pygments/lexer.py:564B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:563                 # it's a state reference
564                 assert tdef != state, f"circular state reference {state!r}"
565                 tokens.extend(cls._process_state(unprocessed, processed,
Bunknownb j��
K./bandit-env/lib/python3.12/site-packages/pip/_vendor/pygments/lexer.py:578B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:577 
578             assert type(tdef) is tuple, f"wrong rule def {tdef!r}"
579 
Bunknownb j��
K./bandit-env/lib/python3.12/site-packages/pip/_vendor/pygments/lexer.py:744B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:743                         else:
744                             assert False, f"wrong state def: {new_state!r}"
745                         statetokens = tokendefs[statestack[-1]]
Bunknownb j��
K./bandit-env/lib/python3.12/site-packages/pip/_vendor/pygments/lexer.py:831B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:830                         else:
831                             assert False, f"wrong state def: {new_state!r}"
832                         statetokens = tokendefs[ctx.stack[-1]]
Bunknownb j��
U./bandit-env/lib/python3.12/site-packages/pip/_vendor/pygments/lexers/__init__.py:154B102	exec_used 0:�Use of exec detected.
code:153         with open(filename, 'rb') as f:
154             exec(f.read(), custom_namespace)
155         # Retrieve the class `lexername` from that namespace
Bunknownb jN�
J./bandit-env/lib/python3.12/site-packages/pip/_vendor/pygments/style.py:79B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:78                 return text
79             assert False, f"wrong color format {text!r}"
80 
Bunknownb j��
P./bandit-env/lib/python3.12/site-packages/pip/_vendor/pyproject_hooks/_impl.py:8B404	blacklist 0:�Consider possible security implications associated with the subprocess module.
code:7 from os.path import join as pjoin
8 from subprocess import STDOUT, check_call, check_output
9 
Bunknownb jN�
Q./bandit-env/lib/python3.12/site-packages/pip/_vendor/pyproject_hooks/_impl.py:59B603$subprocess_without_shell_equals_true 0:psubprocess call - check for execution of untrusted input.
code:58 
59     check_call(cmd, cwd=cwd, env=env)
60 
Bunknownb jN�
Q./bandit-env/lib/python3.12/site-packages/pip/_vendor/pyproject_hooks/_impl.py:71B603$subprocess_without_shell_equals_true 0:�subprocess call - check for execution of untrusted input.
code:70 
71     check_output(cmd, cwd=cwd, env=env, stderr=STDOUT)
72 
Bunknownb jN�
M./bandit-env/lib/python3.12/site-packages/pip/_vendor/requests/__init__.py:53B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:52     urllib3_version = urllib3_version.split(".")
53     assert urllib3_version != ["dev"]  # Verify urllib3 isn't installed from git.
54 
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pip/_vendor/requests/__init__.py:63B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:62     # urllib3 >= 1.21.1
63     assert major >= 1
64     if major == 1:
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pip/_vendor/requests/__init__.py:65B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:64     if major == 1:
65         assert minor >= 21
66 
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pip/_vendor/requests/__init__.py:72B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:71         # chardet_version >= 3.0.2, < 6.0.0
72         assert (3, 0, 2) <= (major, minor, patch) < (6, 0, 0)
73     elif charset_normalizer_version:
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pip/_vendor/requests/__init__.py:77B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:76         # charset_normalizer >= 2.0.0 < 4.0.0
77         assert (2, 0, 0) <= (major, minor, patch) < (4, 0, 0)
78     else:
Bunknownb j��
T./bandit-env/lib/python3.12/site-packages/pip/_vendor/requests/_internal_utils.py:45B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:44     """
45     assert isinstance(u_string, str)
46     try:
Bunknownb j��
J./bandit-env/lib/python3.12/site-packages/pip/_vendor/requests/auth.py:148B324hashlib 0:�Use of weak MD5 hash for security. Consider usedforsecurity=False
code:147                     x = x.encode("utf-8")
148                 return hashlib.md5(x).hexdigest()
149 
Bunknownb j��
J./bandit-env/lib/python3.12/site-packages/pip/_vendor/requests/auth.py:156B324hashlib 0:�Use of weak SHA1 hash for security. Consider usedforsecurity=False
code:155                     x = x.encode("utf-8")
156                 return hashlib.sha1(x).hexdigest()
157 
Bunknownb j��
J./bandit-env/lib/python3.12/site-packages/pip/_vendor/requests/auth.py:205B324hashlib 0:�Use of weak SHA1 hash for security. Consider usedforsecurity=False
code:204 
205         cnonce = hashlib.sha1(s).hexdigest()[:16]
206         if _algorithm == "MD5-SESS":
Bunknownb j��
F./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/_pick.py:13B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:12     """
13     assert values, "1 or more values required"
14     for value in values:
Bunknownb j��
H./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/_ratio.py:129B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:128     total_ratio = sum(ratios)
129     assert total_ratio > 0, "Sum of ratios must be > 0"
130 
Bunknownb j��
P./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/_win32_console.py:436B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:435 
436         assert fore is not None
437         assert back is not None
Bunknownb j��
P./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/_win32_console.py:437B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:436         assert fore is not None
437         assert back is not None
438 
Bunknownb j��
P./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/_win32_console.py:566B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:565         """
566         assert len(title) < 255, "Console title must be less than 255 characters"
567         SetConsoleTitle(title)
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/color.py:365B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:364         if self.type == ColorType.TRUECOLOR:
365             assert self.triplet is not None
366             return self.triplet
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/color.py:368B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:367         elif self.type == ColorType.EIGHT_BIT:
368             assert self.number is not None
369             return EIGHT_BIT_PALETTE[self.number]
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/color.py:371B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:370         elif self.type == ColorType.STANDARD:
371             assert self.number is not None
372             return theme.ansi_colors[self.number]
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/color.py:374B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:373         elif self.type == ColorType.WINDOWS:
374             assert self.number is not None
375             return WINDOWS_PALETTE[self.number]
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/color.py:377B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:376         else:  # self.type == ColorType.DEFAULT:
377             assert self.number is None
378             return theme.foreground_color if foreground else theme.background_color
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/color.py:493B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:492             number = self.number
493             assert number is not None
494             fore, back = (30, 40) if number < 8 else (82, 92)
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/color.py:499B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:498             number = self.number
499             assert number is not None
500             fore, back = (30, 40) if number < 8 else (82, 92)
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/color.py:504B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:503         elif _type == ColorType.EIGHT_BIT:
504             assert self.number is not None
505             return ("38" if foreground else "48", "5", str(self.number))
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/color.py:508B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:507         else:  # self.standard == ColorStandard.TRUECOLOR:
508             assert self.triplet is not None
509             red, green, blue = self.triplet
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/color.py:520B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:519         if system == ColorSystem.EIGHT_BIT and self.system == ColorSystem.TRUECOLOR:
520             assert self.triplet is not None
521             _h, l, s = rgb_to_hls(*self.triplet.normalized)
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/color.py:546B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:545             if self.system == ColorSystem.TRUECOLOR:
546                 assert self.triplet is not None
547                 triplet = self.triplet
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/color.py:549B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:548             else:  # self.system == ColorSystem.EIGHT_BIT
549                 assert self.number is not None
550                 triplet = ColorTriplet(*EIGHT_BIT_PALETTE[self.number])
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/color.py:557B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:556             if self.system == ColorSystem.TRUECOLOR:
557                 assert self.triplet is not None
558                 triplet = self.triplet
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/color.py:560B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:559             else:  # self.system == ColorSystem.EIGHT_BIT
560                 assert self.number is not None
561                 if self.number < 16:
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/color.py:573B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:572     """Parse six hex characters in to RGB triplet."""
573     assert len(hex_color) == 6, "must be 6 characters"
574     color = ColorTriplet(
Bunknownb j��
J./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/console.py:1136B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:1135 
1136         assert count >= 0, "count must be >= 0"
1137         self.print(NewLine(count))
Bunknownb j��
J./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/console.py:1901B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:1900                 offset -= 1
1901             assert frame is not None
1902             return frame.f_code.co_filename, frame.f_lineno, frame.f_locals
Bunknownb j��
T./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/console.py:2138-2139-2140B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:2137         """
2138         assert (
2139             self.record
2140         ), "To export console contents set record=True in the constructor or instance"
2141 
Bunknownb j��
T./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/console.py:2194-2195-2196B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:2193         """
2194         assert (
2195             self.record
2196         ), "To export console contents set record=True in the constructor or instance"
2197         fragments: List[str] = []
Bunknownb j��
E./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/live.py:65B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:64     ) -> None:
65         assert refresh_per_second > 0, "refresh_per_second must be > 0"
66         self._renderable = renderable
Bunknownb j��
F./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/live.py:352B311	blacklist 0:�Standard pseudo-random generators are not suitable for security/cryptographic purposes.
code:351                 time.sleep(0.4)
352                 if random.randint(0, 10) < 1:
353                     console.log(next(examples))
Bunknownb j��
F./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/live.py:355B311	blacklist 0:�Standard pseudo-random generators are not suitable for security/cryptographic purposes.
code:354                 exchange_rate_dict[(select_exchange, exchange)] = 200 / (
355                     (random.random() * 320) + 1
356                 )
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/logging.py:136B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:135             exc_type, exc_value, exc_traceback = record.exc_info
136             assert exc_type is not None
137             assert exc_value is not None
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/logging.py:137B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:136             assert exc_type is not None
137             assert exc_value is not None
138             traceback = Traceback.from_exception(
Bunknownb j��
H./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/pretty.py:191B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:190     console = console or get_console()
191     assert console is not None
192 
Bunknownb j��
H./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/pretty.py:196B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:195         if value is not None:
196             assert console is not None
197             builtins._ = None  # type: ignore[attr-defined]
Bunknownb j��
H./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/pretty.py:497B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:496         )
497         assert self.node is not None
498         return self.node.check_length(start_length, max_length)
Bunknownb j��
H./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/pretty.py:503B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:502         node = self.node
503         assert node is not None
504         whitespace = self.whitespace
Bunknownb j��
H./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/pretty.py:505B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:504         whitespace = self.whitespace
505         assert node.children
506         if node.key_repr:
Bunknownb j��
L./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/pretty.py:642-643B110try_except_pass 0:�Try, Except, Pass detected.
code:641                     rich_repr_result = obj.__rich_repr__()
642             except Exception:
643                 pass
644 
Bunknownb j��
K./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/progress.py:1079B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:1078     ) -> None:
1079         assert refresh_per_second > 0, "refresh_per_second must be > 0"
1080         self._lock = RLock()
Bunknownb j��
K./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/progress.py:1698B311	blacklist 0:�Standard pseudo-random generators are not suitable for security/cryptographic purposes.
code:1697             time.sleep(0.01)
1698             if random.randint(0, 100) < 1:
1699                 progress.log(next(examples))
Bunknownb j��
H./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/prompt.py:214B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:213         """
214         assert self.choices is not None
215         return value.strip() in self.choices
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/style.py:193B311	blacklist 0:�Standard pseudo-random generators are not suitable for security/cryptographic purposes.
code:192         self._link_id = (
193             f"{randint(0, 999999)}{hash(self._meta)}" if (link or meta) else ""
194         )
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/style.py:243B311	blacklist 0:�Standard pseudo-random generators are not suitable for security/cryptographic purposes.
code:242         style._meta = dumps(meta)
243         style._link_id = f"{randint(0, 999999)}{hash(style._meta)}"
244         style._hash = None
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/style.py:475B302	blacklist 0:�Deserialization with the marshal module is possibly dangerous.
code:474         """Get meta information (can not be changed after construction)."""
475         return {} if self._meta is None else cast(Dict[str, Any], loads(self._meta))
476 
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/style.py:490B311	blacklist 0:�Standard pseudo-random generators are not suitable for security/cryptographic purposes.
code:489         style._link = self._link
490         style._link_id = f"{randint(0, 999999)}" if self._link else ""
491         style._null = False
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/style.py:642B311	blacklist 0:�Standard pseudo-random generators are not suitable for security/cryptographic purposes.
code:641         style._link = self._link
642         style._link_id = f"{randint(0, 999999)}" if self._link else ""
643         style._hash = self._hash
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/style.py:688B311	blacklist 0:�Standard pseudo-random generators are not suitable for security/cryptographic purposes.
code:687         style._link = link
688         style._link_id = f"{randint(0, 999999)}" if link else ""
689         style._hash = None
Bunknownb j��
H./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/syntax.py:492B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:491                     """Split tokens to one per line."""
492                     assert lexer  # required to make MyPy happy - we know lexer is not None at this point
493 
Bunknownb j��
F./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/text.py:905B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:904         """
905         assert len(character) == 1, "Character must be a string of length 1"
906         if count:
Bunknownb j��
F./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/text.py:922B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:921         """
922         assert len(character) == 1, "Character must be a string of length 1"
923         if count:
Bunknownb j��
F./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/text.py:938B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:937         """
938         assert len(character) == 1, "Character must be a string of length 1"
939         if count:
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/text.py:1076B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:1075         """
1076         assert separator, "separator must not be empty"
1077 
Bunknownb j��
S./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/traceback.py:282-283-284B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:281             if not isinstance(suppress_entity, str):
282                 assert (
283                     suppress_entity.__file__ is not None
284                 ), f"{suppress_entity!r} must be a module with '__file__' attribute"
285                 path = os.path.dirname(suppress_entity.__file__)
Bunknownb j��
K./bandit-env/lib/python3.12/site-packages/pip/_vendor/rich/traceback.py:644B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:643             if excluded:
644                 assert exclude_frames is not None
645                 yield Text(
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_vendor/typing_extensions.py:313B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:312                             deduped_pairs.remove(pair)
313                     assert not deduped_pairs, deduped_pairs
314                     parameters = tuple(new_parameters)
Bunknownb j��
O./bandit-env/lib/python3.12/site-packages/pip/_vendor/typing_extensions.py:1264B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:1263         def copy_with(self, params):
1264             assert len(params) == 1
1265             new_type = params[0]
Bunknownb j��
O./bandit-env/lib/python3.12/site-packages/pip/_vendor/typing_extensions.py:1643B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:1642                 if len(params) == 1 and not typing._is_param_expr(args[0]):
1643                     assert i == 0
1644                     args = (args,)
Bunknownb j��
O./bandit-env/lib/python3.12/site-packages/pip/_vendor/typing_extensions.py:2351B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:2350         def __typing_unpacked_tuple_args__(self):
2351             assert self.__origin__ is Unpack
2352             assert len(self.__args__) == 1
Bunknownb j��
O./bandit-env/lib/python3.12/site-packages/pip/_vendor/typing_extensions.py:2352B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:2351             assert self.__origin__ is Unpack
2352             assert len(self.__args__) == 1
2353             arg, = self.__args__
Bunknownb j��
O./bandit-env/lib/python3.12/site-packages/pip/_vendor/typing_extensions.py:3114B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:3113         def __new__(cls, typename, bases, ns):
3114             assert _NamedTuple in bases
3115             for base in bases:
Bunknownb j��
O./bandit-env/lib/python3.12/site-packages/pip/_vendor/typing_extensions.py:3185B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:3184     def _namedtuple_mro_entries(bases):
3185         assert NamedTuple in bases
3186         return (_NamedTuple,)
Bunknownb j��
\./bandit-env/lib/python3.12/site-packages/pip/_vendor/urllib3/contrib/securetransport.py:718B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:717             leaf = Security.SecTrustGetCertificateAtIndex(trust, 0)
718             assert leaf
719 
Bunknownb j��
\./bandit-env/lib/python3.12/site-packages/pip/_vendor/urllib3/contrib/securetransport.py:722B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:721             certdata = Security.SecCertificateCopyData(leaf)
722             assert certdata
723 
Bunknownb j��
\./bandit-env/lib/python3.12/site-packages/pip/_vendor/urllib3/contrib/securetransport.py:900B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:899         # See PEP 543 for the real deal.
900         assert not server_side
901         assert do_handshake_on_connect
Bunknownb j��
\./bandit-env/lib/python3.12/site-packages/pip/_vendor/urllib3/contrib/securetransport.py:901B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:900         assert not server_side
901         assert do_handshake_on_connect
902         assert suppress_ragged_eofs
Bunknownb j��
\./bandit-env/lib/python3.12/site-packages/pip/_vendor/urllib3/contrib/securetransport.py:902B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:901         assert do_handshake_on_connect
902         assert suppress_ragged_eofs
903 
Bunknownb j��
_./bandit-env/lib/python3.12/site-packages/pip/_vendor/urllib3/packages/backports/makefile.py:23B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:22     reading = "r" in mode or not writing
23     assert reading or writing
24     binary = "b" in mode
Bunknownb j��
_./bandit-env/lib/python3.12/site-packages/pip/_vendor/urllib3/packages/backports/makefile.py:45B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:44     else:
45         assert writing
46         buffer = io.BufferedWriter(raw, buffering)
Bunknownb j��
h./bandit-env/lib/python3.12/site-packages/pip/_vendor/urllib3/packages/backports/weakref_finalize.py:150B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:149                         sys.excepthook(*sys.exc_info())
150                     assert f not in cls._registry
151         finally:
Bunknownb j��
Q./bandit-env/lib/python3.12/site-packages/pip/_vendor/urllib3/packages/six.py:787B102	exec_used 0:yUse of exec detected.
code:786             _locs_ = _globs_
787         exec ("""exec _code_ in _globs_, _locs_""")
788 
Bunknownb jN�
M./bandit-env/lib/python3.12/site-packages/pip/_vendor/urllib3/response.py:495B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:494         """
495         assert self._fp
496         c_int_max = 2 ** 31 - 1
Bunknownb j��
X./bandit-env/lib/python3.12/site-packages/pip/_vendor/urllib3/util/connection.py:141-142B110try_except_pass 0:yTry, Except, Pass detected.
code:140             has_ipv6 = True
141         except Exception:
142             pass
143 
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/pip/_vendor/urllib3/util/ssl_.py:179B504ssl_with_no_version 0:�ssl.wrap_socket call with no SSL/TLS protocol version specified, the default SSLv23 could be insecure, possible security issue.
code:178             }
179             return wrap_socket(socket, ciphers=self.ciphers, **kwargs)
180 
Bunknownb j��
V./bandit-env/lib/python3.12/site-packages/pip/_vendor/urllib3/util/ssltransport.py:120B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:119         reading = "r" in mode or not writing
120         assert reading or writing
121         binary = "b" in mode
Bunknownb j��
V./bandit-env/lib/python3.12/site-packages/pip/_vendor/urllib3/util/ssltransport.py:142B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:141         else:
142             assert writing
143             buffer = io.BufferedWriter(raw, buffering)
Bunknownb j��
E./bandit-env/lib/python3.12/site-packages/pygments/cmdline.py:522-523B110try_except_pass 0:�Try, Except, Pass detected.
code:521                 width = shutil.get_terminal_size().columns - 2
522             except Exception:
523                 pass
524         argparse.HelpFormatter.__init__(self, prog, indent_increment,
Bunknownb j��
M./bandit-env/lib/python3.12/site-packages/pygments/formatters/__init__.py:103B102	exec_used 0:�Use of exec detected.
code:102         with open(filename, 'rb') as f:
103             exec(f.read(), custom_namespace)
104         # Retrieve the class `formattername` from that namespace
Bunknownb jN�
G./bandit-env/lib/python3.12/site-packages/pygments/formatters/img.py:17B404	blacklist 0:qConsider possible security implications associated with the subprocess module.
code:16 
17 import subprocess
18 
Bunknownb jN�
J./bandit-env/lib/python3.12/site-packages/pygments/formatters/img.py:93-94B607start_process_with_partial_path 0:�Starting a process with a partial executable path
code:92     def _get_nix_font_path(self, name, style):
93         proc = subprocess.Popen(['fc-list', f"{name}:style={style}", 'file'],
94                                 stdout=subprocess.PIPE, stderr=None)
95         stdout, _ = proc.communicate()
Bunknownb jN�
J./bandit-env/lib/python3.12/site-packages/pygments/formatters/img.py:93-94B603$subprocess_without_shell_equals_true 0:�subprocess call - check for execution of untrusted input.
code:92     def _get_nix_font_path(self, name, style):
93         proc = subprocess.Popen(['fc-list', f"{name}:style={style}", 'file'],
94                                 stdout=subprocess.PIPE, stderr=None)
95         stdout, _ = proc.communicate()
Bunknownb jN�
C./bandit-env/lib/python3.12/site-packages/pygments/lexer.py:512-513B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:511         """Preprocess the token component of a token definition."""
512         assert type(token) is _TokenType or callable(token), \
513             f'token type must be simple type or callable, not {token!r}'
514         return token
Bunknownb j��
?./bandit-env/lib/python3.12/site-packages/pygments/lexer.py:529B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:528             else:
529                 assert False, f'unknown new state {new_state!r}'
530         elif isinstance(new_state, combined):
Bunknownb j��
?./bandit-env/lib/python3.12/site-packages/pygments/lexer.py:536B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:535             for istate in new_state:
536                 assert istate != new_state, f'circular state ref {istate!r}'
537                 itokens.extend(cls._process_state(unprocessed,
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pygments/lexer.py:544-545-546B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:543             for istate in new_state:
544                 assert (istate in unprocessed or
545                         istate in ('#pop', '#push')), \
546                     'unknown new state ' + istate
547             return new_state
Bunknownb j��
?./bandit-env/lib/python3.12/site-packages/pygments/lexer.py:549B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:548         else:
549             assert False, f'unknown new state def {new_state!r}'
550 
Bunknownb j��
?./bandit-env/lib/python3.12/site-packages/pygments/lexer.py:553B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:552         """Preprocess a single state definition."""
553         assert isinstance(state, str), f"wrong state name {state!r}"
554         assert state[0] != '#', f"invalid state name {state!r}"
Bunknownb j��
?./bandit-env/lib/python3.12/site-packages/pygments/lexer.py:554B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:553         assert isinstance(state, str), f"wrong state name {state!r}"
554         assert state[0] != '#', f"invalid state name {state!r}"
555         if state in processed:
Bunknownb j��
?./bandit-env/lib/python3.12/site-packages/pygments/lexer.py:562B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:561                 # it's a state reference
562                 assert tdef != state, f"circular state reference {state!r}"
563                 tokens.extend(cls._process_state(unprocessed, processed,
Bunknownb j��
?./bandit-env/lib/python3.12/site-packages/pygments/lexer.py:576B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:575 
576             assert type(tdef) is tuple, f"wrong rule def {tdef!r}"
577 
Bunknownb j��
?./bandit-env/lib/python3.12/site-packages/pygments/lexer.py:742B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:741                         else:
742                             assert False, f"wrong state def: {new_state!r}"
743                         statetokens = tokendefs[statestack[-1]]
Bunknownb j��
?./bandit-env/lib/python3.12/site-packages/pygments/lexer.py:829B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:828                         else:
829                             assert False, f"wrong state def: {new_state!r}"
830                         statetokens = tokendefs[ctx.stack[-1]]
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/pygments/lexers/__init__.py:154B102	exec_used 0:�Use of exec detected.
code:153         with open(filename, 'rb') as f:
154             exec(f.read(), custom_namespace)
155         # Retrieve the class `lexername` from that namespace
Bunknownb jN�
N./bandit-env/lib/python3.12/site-packages/pygments/lexers/_lua_builtins.py:225B310	blacklist 0:�Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.
code:224     def get_newest_version():
225         f = urlopen('http://www.lua.org/manual/')
226         r = re.compile(r'^<A HREF="(\d\.\d)/">(Lua )?\1</A>')
Bunknownb j�
N./bandit-env/lib/python3.12/site-packages/pygments/lexers/_lua_builtins.py:233B310	blacklist 0:�Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.
code:232     def get_lua_functions(version):
233         f = urlopen(f'http://www.lua.org/manual/{version}/')
234         r = re.compile(r'^<A HREF="manual.html#pdf-(?!lua|LUA)([^:]+)">\1</A>')
Bunknownb j�
Q./bandit-env/lib/python3.12/site-packages/pygments/lexers/_mysql_builtins.py:1248B310	blacklist 0:�Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.
code:1247         # Pull content from lex.h.
1248         lex_file = urlopen(LEX_URL).read().decode('utf8', errors='ignore')
1249         keywords = parse_lex_keywords(lex_file)
Bunknownb j�
Q./bandit-env/lib/python3.12/site-packages/pygments/lexers/_mysql_builtins.py:1254B310	blacklist 0:�Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.
code:1253         # Parse content in item_create.cc.
1254         item_create_file = urlopen(ITEM_CREATE_URL).read().decode('utf8', errors='ignore')
1255         functions.update(parse_item_create_functions(item_create_file))
Bunknownb j�
O./bandit-env/lib/python3.12/site-packages/pygments/lexers/_php_builtins.py:3299B310	blacklist 0:�Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.
code:3298     def get_php_references():
3299         download = urlretrieve(PHP_MANUAL_URL)
3300         with tarfile.open(download[0]) as tar:
Bunknownb j�
O./bandit-env/lib/python3.12/site-packages/pygments/lexers/_php_builtins.py:3301B202tarfile_unsafe_members 0:�tarfile.extractall used without any validation. Please check and discard dangerous members.
code:3300         with tarfile.open(download[0]) as tar:
3301             tar.extractall()
3302         yield from glob.glob(f"{PHP_MANUAL_DIR}{PHP_REFERENCE_GLOB}")
Bunknownb j�
S./bandit-env/lib/python3.12/site-packages/pygments/lexers/_postgres_builtins.py:642B310	blacklist 0:�Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.
code:641     def update_myself():
642         content = urlopen(DATATYPES_URL).read().decode('utf-8', errors='ignore')
643         data_file = list(content.splitlines())
Bunknownb j�
S./bandit-env/lib/python3.12/site-packages/pygments/lexers/_postgres_builtins.py:647B310	blacklist 0:�Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.
code:646 
647         content = urlopen(KEYWORDS_URL).read().decode('utf-8', errors='ignore')
648         keywords = parse_keywords(content)
Bunknownb j�
R./bandit-env/lib/python3.12/site-packages/pygments/lexers/_scilab_builtins.py:3055B404	blacklist 0:�Consider possible security implications associated with the subprocess module.
code:3054 if __name__ == '__main__':  # pragma: no cover
3055     import subprocess
3056     from pygments.util import format_lines, duplicates_removed
Bunknownb jN�
W./bandit-env/lib/python3.12/site-packages/pygments/lexers/_scilab_builtins.py:3061-3062B607start_process_with_partial_path 0:�Starting a process with a partial executable path
code:3060     def extract_completion(var_type):
3061         s = subprocess.Popen(['scilab', '-nwni'], stdin=subprocess.PIPE,
3062                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
3063         output = s.communicate(f'''\
Bunknownb jN�
W./bandit-env/lib/python3.12/site-packages/pygments/lexers/_scilab_builtins.py:3061-3062B603$subprocess_without_shell_equals_true 0:�subprocess call - check for execution of untrusted input.
code:3060     def extract_completion(var_type):
3061         s = subprocess.Popen(['scilab', '-nwni'], stdin=subprocess.PIPE,
3062                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
3063         output = s.communicate(f'''\
Bunknownb jN�
L./bandit-env/lib/python3.12/site-packages/pygments/lexers/int_fiction.py:728B105hardcoded_password_string 0:�Possible hardcoded password: 'root'
code:727         for token in Inform6Lexer.tokens:
728             if token == 'root':
729                 continue
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/pygments/lexers/jsonnet.py:17B105hardcoded_password_string 0:�Possible hardcoded password: '[^\W\d]\w*'
code:16 
17 jsonnet_token = r'[^\W\d]\w*'
18 jsonnet_function_token = jsonnet_token + r'(?=\()'
Bunknownb j��
H./bandit-env/lib/python3.12/site-packages/pygments/lexers/lilypond.py:43B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:42     else:
43         assert backslash == "disallowed"
44     return words(names, prefix, suffix)
Bunknownb j��
\./bandit-env/lib/python3.12/site-packages/pygments/lexers/lisp.py:50-51-52-53-54-55-56-57-58B105hardcoded_password_string 0:�Possible hardcoded password: '
      (?=
        \s         # whitespace
        | ;        # comment
        | \#[;|!] # fancy comments
        | [)\]]    # end delimiters
        | $        # end of file
      )
    '
code:49     # Use within verbose regexes
50     token_end = r'''
51       (?=
52         \s         # whitespace
53         | ;        # comment
54         | \#[;|!] # fancy comments
55         | [)\]]    # end delimiters
56         | $        # end of file
57       )
58     '''
59 
Bunknownb j��
F./bandit-env/lib/python3.12/site-packages/pygments/lexers/lisp.py:3041B105hardcoded_password_string 0:�Possible hardcoded password: '(?=\s|#|[)\]]|$)'
code:3040     # ...so, express it like this
3041     _token_end = r'(?=\s|#|[)\]]|$)'
3042 
Bunknownb j��
H./bandit-env/lib/python3.12/site-packages/pygments/lexers/parsers.py:334B105hardcoded_password_string 0:�Possible hardcoded password: '[A-Z]\w*'
code:333     _id = r'[A-Za-z]\w*'
334     _TOKEN_REF = r'[A-Z]\w*'
335     _RULE_REF = r'[a-z]\w*'
Bunknownb j��
K./bandit-env/lib/python3.12/site-packages/pygments/lexers/scripting.py:1459B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:1458                         result += 0.01
1459         assert 0.0 <= result <= 1.0
1460         return result
Bunknownb j��
K./bandit-env/lib/python3.12/site-packages/pygments/lexers/scripting.py:1543B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:1542                 result = 1.0
1543         assert 0.0 <= result <= 1.0
1544         return result
Bunknownb j��
D./bandit-env/lib/python3.12/site-packages/pygments/lexers/sql.py:233B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:232     else:
233         assert 0, "SQL keywords not found"
234 
Bunknownb j��
>./bandit-env/lib/python3.12/site-packages/pygments/style.py:79B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:78                 return text
79             assert False, f"wrong color format {text!r}"
80 
Bunknownb j��
:./bandit-env/lib/python3.12/site-packages/rich/_pick.py:13B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:12     """
13     assert values, "1 or more values required"
14     for value in values:
Bunknownb j��
<./bandit-env/lib/python3.12/site-packages/rich/_ratio.py:129B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:128     total_ratio = sum(ratios)
129     assert total_ratio > 0, "Sum of ratios must be > 0"
130 
Bunknownb j��
D./bandit-env/lib/python3.12/site-packages/rich/_win32_console.py:436B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:435 
436         assert fore is not None
437         assert back is not None
Bunknownb j��
D./bandit-env/lib/python3.12/site-packages/rich/_win32_console.py:437B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:436         assert fore is not None
437         assert back is not None
438 
Bunknownb j��
D./bandit-env/lib/python3.12/site-packages/rich/_win32_console.py:566B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:565         """
566         assert len(title) < 255, "Console title must be less than 255 characters"
567         SetConsoleTitle(title)
Bunknownb j��
;./bandit-env/lib/python3.12/site-packages/rich/color.py:365B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:364         if self.type == ColorType.TRUECOLOR:
365             assert self.triplet is not None
366             return self.triplet
Bunknownb j��
;./bandit-env/lib/python3.12/site-packages/rich/color.py:368B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:367         elif self.type == ColorType.EIGHT_BIT:
368             assert self.number is not None
369             return EIGHT_BIT_PALETTE[self.number]
Bunknownb j��
;./bandit-env/lib/python3.12/site-packages/rich/color.py:371B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:370         elif self.type == ColorType.STANDARD:
371             assert self.number is not None
372             return theme.ansi_colors[self.number]
Bunknownb j��
;./bandit-env/lib/python3.12/site-packages/rich/color.py:374B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:373         elif self.type == ColorType.WINDOWS:
374             assert self.number is not None
375             return WINDOWS_PALETTE[self.number]
Bunknownb j��
;./bandit-env/lib/python3.12/site-packages/rich/color.py:377B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:376         else:  # self.type == ColorType.DEFAULT:
377             assert self.number is None
378             return theme.foreground_color if foreground else theme.background_color
Bunknownb j��
;./bandit-env/lib/python3.12/site-packages/rich/color.py:493B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:492             number = self.number
493             assert number is not None
494             fore, back = (30, 40) if number < 8 else (82, 92)
Bunknownb j��
;./bandit-env/lib/python3.12/site-packages/rich/color.py:499B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:498             number = self.number
499             assert number is not None
500             fore, back = (30, 40) if number < 8 else (82, 92)
Bunknownb j��
;./bandit-env/lib/python3.12/site-packages/rich/color.py:504B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:503         elif _type == ColorType.EIGHT_BIT:
504             assert self.number is not None
505             return ("38" if foreground else "48", "5", str(self.number))
Bunknownb j��
;./bandit-env/lib/python3.12/site-packages/rich/color.py:508B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:507         else:  # self.standard == ColorStandard.TRUECOLOR:
508             assert self.triplet is not None
509             red, green, blue = self.triplet
Bunknownb j��
;./bandit-env/lib/python3.12/site-packages/rich/color.py:520B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:519         if system == ColorSystem.EIGHT_BIT and self.system == ColorSystem.TRUECOLOR:
520             assert self.triplet is not None
521             _h, l, s = rgb_to_hls(*self.triplet.normalized)
Bunknownb j��
;./bandit-env/lib/python3.12/site-packages/rich/color.py:546B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:545             if self.system == ColorSystem.TRUECOLOR:
546                 assert self.triplet is not None
547                 triplet = self.triplet
Bunknownb j��
;./bandit-env/lib/python3.12/site-packages/rich/color.py:549B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:548             else:  # self.system == ColorSystem.EIGHT_BIT
549                 assert self.number is not None
550                 triplet = ColorTriplet(*EIGHT_BIT_PALETTE[self.number])
Bunknownb j��
;./bandit-env/lib/python3.12/site-packages/rich/color.py:557B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:556             if self.system == ColorSystem.TRUECOLOR:
557                 assert self.triplet is not None
558                 triplet = self.triplet
Bunknownb j��
;./bandit-env/lib/python3.12/site-packages/rich/color.py:560B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:559             else:  # self.system == ColorSystem.EIGHT_BIT
560                 assert self.number is not None
561                 if self.number < 16:
Bunknownb j��
;./bandit-env/lib/python3.12/site-packages/rich/color.py:573B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:572     """Parse six hex characters in to RGB triplet."""
573     assert len(hex_color) == 6, "must be 6 characters"
574     color = ColorTriplet(
Bunknownb j��
>./bandit-env/lib/python3.12/site-packages/rich/console.py:1135B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:1134 
1135         assert count >= 0, "count must be >= 0"
1136         self.print(NewLine(count))
Bunknownb j��
>./bandit-env/lib/python3.12/site-packages/rich/console.py:1911B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:1910                 offset -= 1
1911             assert frame is not None
1912             return frame.f_code.co_filename, frame.f_lineno, frame.f_locals
Bunknownb j��
H./bandit-env/lib/python3.12/site-packages/rich/console.py:2171-2172-2173B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:2170         """
2171         assert (
2172             self.record
2173         ), "To export console contents set record=True in the constructor or instance"
2174 
Bunknownb j��
H./bandit-env/lib/python3.12/site-packages/rich/console.py:2227-2228-2229B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:2226         """
2227         assert (
2228             self.record
2229         ), "To export console contents set record=True in the constructor or instance"
2230         fragments: List[str] = []
Bunknownb j��
9./bandit-env/lib/python3.12/site-packages/rich/live.py:65B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:64     ) -> None:
65         assert refresh_per_second > 0, "refresh_per_second must be > 0"
66         self._renderable = renderable
Bunknownb j��
:./bandit-env/lib/python3.12/site-packages/rich/live.py:352B311	blacklist 0:�Standard pseudo-random generators are not suitable for security/cryptographic purposes.
code:351                 time.sleep(0.4)
352                 if random.randint(0, 10) < 1:
353                     console.log(next(examples))
Bunknownb j��
:./bandit-env/lib/python3.12/site-packages/rich/live.py:355B311	blacklist 0:�Standard pseudo-random generators are not suitable for security/cryptographic purposes.
code:354                 exchange_rate_dict[(select_exchange, exchange)] = 200 / (
355                     (random.random() * 320) + 1
356                 )
Bunknownb j��
=./bandit-env/lib/python3.12/site-packages/rich/logging.py:142B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:141             exc_type, exc_value, exc_traceback = record.exc_info
142             assert exc_type is not None
143             assert exc_value is not None
Bunknownb j��
=./bandit-env/lib/python3.12/site-packages/rich/logging.py:143B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:142             assert exc_type is not None
143             assert exc_value is not None
144             traceback = Traceback.from_exception(
Bunknownb j��
>./bandit-env/lib/python3.12/site-packages/rich/markdown.py:270B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:269     def on_child_close(self, context: MarkdownContext, child: MarkdownElement) -> bool:
270         assert isinstance(child, TableRowElement)
271         self.row = child
Bunknownb j��
>./bandit-env/lib/python3.12/site-packages/rich/markdown.py:282B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:281     def on_child_close(self, context: MarkdownContext, child: MarkdownElement) -> bool:
282         assert isinstance(child, TableRowElement)
283         self.rows.append(child)
Bunknownb j��
>./bandit-env/lib/python3.12/site-packages/rich/markdown.py:294B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:293     def on_child_close(self, context: MarkdownContext, child: MarkdownElement) -> bool:
294         assert isinstance(child, TableDataElement)
295         self.cells.append(child)
Bunknownb j��
>./bandit-env/lib/python3.12/site-packages/rich/markdown.py:317B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:316 
317         assert justify in get_args(JustifyMethod)
318         return cls(justify=justify)
Bunknownb j��
>./bandit-env/lib/python3.12/site-packages/rich/markdown.py:343B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:342     def on_child_close(self, context: MarkdownContext, child: MarkdownElement) -> bool:
343         assert isinstance(child, ListItem)
344         self.items.append(child)
Bunknownb j��
>./bandit-env/lib/python3.12/site-packages/rich/markdown.py:614B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:613                     element = context.stack.pop()
614                     assert isinstance(element, Link)
615                     link_style = console.get_style("markdown.link", default="none")
Bunknownb j��
<./bandit-env/lib/python3.12/site-packages/rich/pretty.py:198B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:197     console = console or get_console()
198     assert console is not None
199 
Bunknownb j��
<./bandit-env/lib/python3.12/site-packages/rich/pretty.py:203B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:202         if value is not None:
203             assert console is not None
204             builtins._ = None  # type: ignore[attr-defined]
Bunknownb j��
<./bandit-env/lib/python3.12/site-packages/rich/pretty.py:516B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:515         )
516         assert self.node is not None
517         return self.node.check_length(start_length, max_length)
Bunknownb j��
<./bandit-env/lib/python3.12/site-packages/rich/pretty.py:522B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:521         node = self.node
522         assert node is not None
523         whitespace = self.whitespace
Bunknownb j��
<./bandit-env/lib/python3.12/site-packages/rich/pretty.py:524B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:523         whitespace = self.whitespace
524         assert node.children
525         if node.key_repr:
Bunknownb j��
@./bandit-env/lib/python3.12/site-packages/rich/pretty.py:661-662B110try_except_pass 0:�Try, Except, Pass detected.
code:660                     rich_repr_result = obj.__rich_repr__()
661             except Exception:
662                 pass
663 
Bunknownb j��
?./bandit-env/lib/python3.12/site-packages/rich/progress.py:1085B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:1084     ) -> None:
1085         assert refresh_per_second > 0, "refresh_per_second must be > 0"
1086         self._lock = RLock()
Bunknownb j��
?./bandit-env/lib/python3.12/site-packages/rich/progress.py:1706B311	blacklist 0:�Standard pseudo-random generators are not suitable for security/cryptographic purposes.
code:1705             time.sleep(0.01)
1706             if random.randint(0, 100) < 1:
1707                 progress.log(next(examples))
Bunknownb j��
<./bandit-env/lib/python3.12/site-packages/rich/prompt.py:222B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:221         """
222         assert self.choices is not None
223         if self.case_sensitive:
Bunknownb j��
;./bandit-env/lib/python3.12/site-packages/rich/style.py:193B311	blacklist 0:�Standard pseudo-random generators are not suitable for security/cryptographic purposes.
code:192         self._link_id = (
193             f"{randint(0, 999999)}{hash(self._meta)}" if (link or meta) else ""
194         )
Bunknownb j��
;./bandit-env/lib/python3.12/site-packages/rich/style.py:243B311	blacklist 0:�Standard pseudo-random generators are not suitable for security/cryptographic purposes.
code:242         style._meta = dumps(meta)
243         style._link_id = f"{randint(0, 999999)}{hash(style._meta)}"
244         style._hash = None
Bunknownb j��
;./bandit-env/lib/python3.12/site-packages/rich/style.py:475B302	blacklist 0:�Deserialization with the marshal module is possibly dangerous.
code:474         """Get meta information (can not be changed after construction)."""
475         return {} if self._meta is None else cast(Dict[str, Any], loads(self._meta))
476 
Bunknownb j��
;./bandit-env/lib/python3.12/site-packages/rich/style.py:490B311	blacklist 0:�Standard pseudo-random generators are not suitable for security/cryptographic purposes.
code:489         style._link = self._link
490         style._link_id = f"{randint(0, 999999)}" if self._link else ""
491         style._null = False
Bunknownb j��
;./bandit-env/lib/python3.12/site-packages/rich/style.py:642B311	blacklist 0:�Standard pseudo-random generators are not suitable for security/cryptographic purposes.
code:641         style._link = self._link
642         style._link_id = f"{randint(0, 999999)}" if self._link else ""
643         style._hash = self._hash
Bunknownb j��
;./bandit-env/lib/python3.12/site-packages/rich/style.py:688B311	blacklist 0:�Standard pseudo-random generators are not suitable for security/cryptographic purposes.
code:687         style._link = link
688         style._link_id = f"{randint(0, 999999)}" if link else ""
689         style._hash = None
Bunknownb j��
<./bandit-env/lib/python3.12/site-packages/rich/syntax.py:491B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:490                     """Split tokens to one per line."""
491                     assert lexer  # required to make MyPy happy - we know lexer is not None at this point
492 
Bunknownb j��
:./bandit-env/lib/python3.12/site-packages/rich/text.py:905B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:904         """
905         assert len(character) == 1, "Character must be a string of length 1"
906         if count:
Bunknownb j��
:./bandit-env/lib/python3.12/site-packages/rich/text.py:922B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:921         """
922         assert len(character) == 1, "Character must be a string of length 1"
923         if count:
Bunknownb j��
:./bandit-env/lib/python3.12/site-packages/rich/text.py:938B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:937         """
938         assert len(character) == 1, "Character must be a string of length 1"
939         if count:
Bunknownb j��
;./bandit-env/lib/python3.12/site-packages/rich/text.py:1077B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:1076         """
1077         assert separator, "separator must not be empty"
1078 
Bunknownb j��
G./bandit-env/lib/python3.12/site-packages/rich/traceback.py:285-286-287B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:284             if not isinstance(suppress_entity, str):
285                 assert (
286                     suppress_entity.__file__ is not None
287                 ), f"{suppress_entity!r} must be a module with '__file__' attribute"
288                 path = os.path.dirname(suppress_entity.__file__)
Bunknownb j��
?./bandit-env/lib/python3.12/site-packages/rich/traceback.py:650B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:649             if excluded:
650                 assert exclude_frames is not None
651                 yield Text(
Bunknownb j��
J./bandit-env/lib/python3.12/site-packages/stevedore/tests/test_cache.py:29B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:28         """
29         with mock.patch.object(sys, 'executable', '/tmp/fake'):
30             sot = _cache.Cache()
Bunknownb j��
N./bandit-env/lib/python3.12/site-packages/stevedore/tests/test_extension.py:78B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:77         else:
78             assert False, 'Failed to raise KeyError'
79 
Bunknownb j��
O./bandit-env/lib/python3.12/site-packages/stevedore/tests/test_extension.py:175B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:174             em.map(mapped, 1, 2, a='A', b='B')
175             assert False
176         except RuntimeError:
Bunknownb j��
I./bandit-env/lib/python3.12/site-packages/stevedore/tests/test_hook.py:55B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:54         else:
55             assert False, 'Failed to raise KeyError'
Bunknownb j��
R./bandit-env/lib/python3.12/site-packages/stevedore/tests/test_test_manager.py:132B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:131         # This will raise KeyError if the names don't match
132         assert (em[test_extension.name])
133 
Bunknownb j��
<./bandit-env/lib/python3.12/site-packages/yaml/parser.py:185B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:184             event = StreamEndEvent(token.start_mark, token.end_mark)
185             assert not self.states
186             assert not self.marks
Bunknownb j��
<./bandit-env/lib/python3.12/site-packages/yaml/parser.py:186B101assert_used 0:�Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
code:185             assert not self.states
186             assert not self.marks
187             self.state = None
Bunknownb j��
./good/cutpasswd.py:3B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:2 
3 with open('/tmp/darkweb2017-top10000.txt') as f:
4     for password in f.readlines():
Bunknownb j��
./good/httpbrute.py:22B113request_without_timeout 0:�Requests call without timeout
code:21 for password in passwords:
22     response = requests.post(URL, data = {'username': username, 'password': password})
23     if 'HOME' in response.text:
Bunknownb j��
./good/libapi.py:10B105hardcoded_password_string 0:tPossible hardcoded password: 'MYSUPERSECRETKEY'
code:9 
10 secret = 'MYSUPERSECRETKEY'
11 not_after = 60 # 1 minute
Bunknownb j��
./good/libsession.py:22-23B110try_except_pass 0:xTry, Except, Pass detected.
code:21         country = geo.country.iso_code
22     except Exception:
23         pass
24 
Bunknownb j��
./good/libuser.py:61B608hardcoded_sql_expressions 0:�Possible SQL injection vector through string-based query construction.
code:60     c = conn.cursor()
61     c.execute("INSERT INTO users (username, password, salt, failures, mfa_enabled, mfa_secret) VALUES ('%s', '%s', '%s', '%d', '%d', '%s')" %(username, '', '', 0, 0, ''))
62     conn.commit()
Bunknownb jY�
./good/vulpy-ssl.py:13B105hardcoded_password_string 0:pPossible hardcoded password: 'aaaaaaa'
code:12 app = Flask('vulpy')
13 app.config['SECRET_KEY'] = 'aaaaaaa'
14 
Bunknownb j��
./good/vulpy-ssl.py:29B201flask_debug_true 0:�A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.
code:28 
29 app.run(debug=True, host='127.0.1.1', ssl_context=('/tmp/acme.cert', '/tmp/acme.key'))
Bunknownb j^�
./good/vulpy-ssl.py:29B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:28 
29 app.run(debug=True, host='127.0.1.1', ssl_context=('/tmp/acme.cert', '/tmp/acme.key'))
Bunknownb j��
./good/vulpy-ssl.py:29B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:28 
29 app.run(debug=True, host='127.0.1.1', ssl_context=('/tmp/acme.cert', '/tmp/acme.key'))
Bunknownb j��
./good/vulpy.py:17B105hardcoded_password_string 0:�Possible hardcoded password: '123aa8a93bdde342c871564a62282af857bda14b3359fde95d0c5e4b321610c1'
code:16 app = Flask('vulpy')
17 app.config['SECRET_KEY'] = '123aa8a93bdde342c871564a62282af857bda14b3359fde95d0c5e4b321610c1'
18 
Bunknownb j��
./good/vulpy.py:53B201flask_debug_true 0:�A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.
code:52 
53 app.run(debug=True, host='127.0.1.1', port=5001, extra_files='csp.txt')
54 
Bunknownb j^�
./utils/ca-create.py:31B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:30 
31 with open('/tmp/ca.key', 'wb') as out:
32     out.write(pem_private)
Bunknownb j��
./utils/ca-create.py:34B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:33 
34 with open('/tmp/ca.pub', 'wb') as out:
35     out.write(pem_public)
Bunknownb j��
./utils/ca-create.py:58B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:57 # Write our certificate out to disk.
58 with open('/tmp/ca.cert', 'wb') as out:
59     out.write(cert.public_bytes(serialization.Encoding.PEM))
Bunknownb j��
./utils/ca-csr-create.py:12B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:11 
12 with open("/tmp/acme.key", "rb") as key_file:
13     private_key = serialization.load_pem_private_key(
Bunknownb j��
./utils/ca-csr-create.py:35B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:34 # Write our CSR out to disk.
35 with open("/tmp/acme.csr", "wb") as out:
36     out.write(csr.public_bytes(serialization.Encoding.PEM))
Bunknownb j��
./utils/ca-csr-load.py:13B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:12 
13 with open("/tmp/ca.cert", "rb") as ca_cert_file:
14     ca_cert = x509.load_pem_x509_certificate(ca_cert_file.read(), default_backend())
Bunknownb j��
./utils/ca-csr-load.py:16B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:15 
16 with open("/tmp/acme.csr", "rb") as csr_file:
17     csr = x509.load_pem_x509_csr(csr_file.read(), default_backend())
Bunknownb j��
./utils/ca-csr-load.py:19B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:18 
19 with open("/tmp/ca.key", "rb") as key_file:
20     private_key = serialization.load_pem_private_key(
Bunknownb j��
./utils/ca-csr-load.py:35B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:34 # Write our certificate out to disk.
35 with open('/tmp/acme.cert', 'wb') as out:
36     out.write(cert.public_bytes(serialization.Encoding.PEM))
Bunknownb j��
$./utils/generate_bad_passwords.py:21B113request_without_timeout 0:�Requests call without timeout
code:20     click.echo('Downloading password file...', nl=False, err=True)
21     with requests.get(url, stream=True) as r:
22         r.raise_for_status()
Bunknownb j��
./utils/httpbrute.py:25B113request_without_timeout 0:�Requests call without timeout
code:24     for password in passwords:
25         response = requests.post(url, data = {'username': username, 'password': password})
26         logging.info('{} {} {}'.format(username, password, response.status_code))
Bunknownb j��
./utils/rsa-decrypt.py:14B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:13 
14 with open("/tmp/acme.key", "rb") as key_file:
15     private_key = serialization.load_pem_private_key(
Bunknownb j��
./utils/rsa-encrypt.py:14B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:13 
14 with open("/tmp/acme.pub", "rb") as key_file:
15     public_key = serialization.load_pem_public_key(
Bunknownb j��
./utils/rsa-keygen.py:26B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:25 
26 with open('/tmp/acme.key', 'wb') as out:
27     out.write(pem_private)
Bunknownb j��
./utils/rsa-keygen.py:29B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:28 
29 with open('/tmp/acme.pub', 'wb') as out:
30     out.write(pem_public)
Bunknownb j��
./utils/rsa-sign.py:15B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:14 
15 with open("/tmp/acme.key", "rb") as key_file:
16     private_key = serialization.load_pem_private_key(
Bunknownb j��
./utils/rsa-verify.py:16B108hardcoded_tmp_directory 0:�Probable insecure usage of temp file/directory.
code:15 
16 with open("/tmp/acme.pub", "rb") as key_file:
17     public_key = serialization.load_pem_public_key(
Bunknownb j�