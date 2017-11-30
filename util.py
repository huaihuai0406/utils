#!/usr/bin/env python
# -*- coding:utf8 -*-
#

class htmlfind:
    def __init__(self, html, reg, which):
        self.s = ''
        self.start = 0
        self.which = 0
        self._begin(html, reg, which)

    def _begin(self, s, reg, which):
        if isinstance(s, unicode):
            s = s.encode('utf-8')
        regtype = type(re.compile(''))
        if isinstance(reg, unicode) or isinstance(reg, str) or isinstance(reg, regtype):
            reg = [reg]
        if not isinstance(reg, list):
            raise RuntimeError("unknown type")
        start = 0
        for r in reg:
            if isinstance(r, unicode):
                r = r.encode('utf-8')
            if isinstance(r, str):
                m = re.search(r, s, start)
            elif isinstance(r, regtype):
                m = r.search(s, start)
            else:
                raise RuntimeError("unknown type")
            if m is not None:
                start = m.end(0)
            else:
                start = len(s)
                break
        self.s = s
        self.start = start
        self.which = which

    def process_form(self):
        return cutil.process_form(self.s, self.start, self.which)

    def get_node(self):
        return cutil.get_html_node(self.s, self.start, self.which)

    def get_text(self):
        return cutil.get_html_text(self.s, self.start, self.which)

    def get_text_hash(self):
        return cutil.get_html_text_hash(self.s, self.start, self.which)

    @staticmethod
    def findTag(doc, tag, attr=None, text_pattern=None):
        pat = None
        if not attr and not text_pattern:
            pat = ur'<{}[^<>]*>(.*?)</{}>'.format(tag, tag)
        elif not attr and text_pattern:
            pat = ur'<{}[^>]*?>{}</{}>'.format(tag, text_pattern, tag)
        elif attr and not text_pattern:
            pat = ur'<{}[^>]*{}[^>]*>(.*?)</{}>'.format(tag, attr, tag)
        elif attr and text_pattern:
            pat = ur'<{}[^>]*{}[^>]*>{}</{}>'.format(tag, attr, text_pattern, tag)

        els = re.findall(pat, doc, re.S)
        return els

    @staticmethod
    def remove_tag(s, fmt=False):
        if fmt:
            r = re.sub(r'<br>|<p>|<BR>', '\n', s)
            r = re.sub(r'(<[^>]*>)', '', r)
            r = re.sub(r'&nbsp;', ' ', r)
            r = re.sub(r'[\t\r ]+', ' ', r)
            r = re.sub(r'\s+\n+\s+', '\n', r)
            r = re.sub(r'^\s+|\s+$', '', r)
        else:
            r = re.sub(r'(<[^>]*>)', '', s)
            r = re.sub(r'&nbsp;', ' ', r)
        return r


def runjs(jscode):
    jscode = utf8str(jscode)
    nodeapp = which("node")
    # nodeapp = '/usr/local/bin/node'
    if nodeapp is None:
        nodeapp = which("nodejs")
    if nodeapp is None:
        raise RuntimeError("nodejs is NOT found!")
    node = subprocess.Popen(nodeapp, stdin=subprocess.PIPE, stdout=subprocess.PIPE, close_fds=True,
                            bufsize=len(jscode) + 1)
    node.stdin.write(jscode)
    node.stdin.close()
    ooo = ''
    while True:
        oo1 = node.stdout.read(1024)
        if not oo1:
            break
        ooo += oo1
    node.wait()

    if node.returncode == 0:
        return ooo
    else:
        raise RuntimeError("execute js failed.", node.returncode, ooo)


def which(program):
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        # print os.environ["PATH"]
        for path in os.environ["PATH"].split(os.pathsep):

            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file
    return None


class TimeHandler(object):
    @staticmethod
    def isFontDate(datestr):
        return re.match(r'(&#x[\d\w]{4};){4}-(&#x[\d\w]{4};){2}-(&#x[\d\w]{4};){2}', datestr)

    @staticmethod
    def cv58fontDateCvt(datestr):
        if not TimeHandler.isFontDate(datestr):
            return datestr
        ds = re.sub('-', '', datestr.replace('&#', '0'))
        numstrs = ds.split(';')
        retstr = ['2']
        relInt = int(numstrs[0], 16)
        for numstr in numstrs[1:8]:
            retstr.append(str(int(numstr, 16) - relInt + 2))
        return '%s-%s-%s' % (''.join(retstr[:4]), ''.join(retstr[4:6]), ''.join(retstr[6:]))

    @staticmethod
    def isBeforeNDay(t, day):
        if isinstance(t, str) or isinstance(t, unicode):
            m = re.search('(\d+)-(\d+)-(\d+).*?(\d+):(\d+):(\d+)', t)
            if m:
                arr = [int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)),
                       int(m.group(6)), 0, 0, 0]
                t = time.mktime(arr)
                if time.time() - t > 3600 * 24 * day:
                    return True

        if isinstance(t, int):
            if int(time.time()) - t / 1000 > 3600 * 24 * day:
                return True
        return False

    @staticmethod
    def getTimeOfNDayBefore(day):
        day = int(day)
        one_day = 24 * 3600
        nday_before = time.time() - day * one_day
        return int(nday_before * 1000)

    @staticmethod
    def fmt_time(tag):
        if isinstance(tag, unicode):
            tag = tag.encode('utf-8')

        now_time = list(time.localtime())

        t = re.search(r'(\d+):(\d+)', tag)
        if t:
            now_time[3] = int(t.group(1))
            now_time[4] = int(t.group(2))
            return int(time.mktime(now_time) * 1000)

        t = re.search(r'(\d+)-(\d+)-(\d+)', tag)
        if t:
            now_time[0] = int(t.group(1))
            now_time[1] = int(t.group(2))
            now_time[2] = int(t.group(3))
            return int(time.mktime(now_time) * 1000)

        t = re.search(r'(\d+)-(\d+)', tag)
        if t:
            now_time[1] = int(t.group(1))
            now_time[2] = int(t.group(2))
            return int(time.mktime(now_time) * 1000)

        t = re.search(r'(\d+)/(\d+)/(\d+)', tag)
        if t:
            now_time[0] = int(t.group(1))
            now_time[1] = int(t.group(2))
            now_time[2] = int(t.group(3))
            return int(time.mktime(now_time) * 1000)

        t = re.search(r'(\d+)小时', tag)
        if t:
            hour = int(t.group(1))
            return int(time.time() - hour * 3600) * 1000

        t = re.search(r'(\d+)分钟', tag)
        if t:
            minute = int(t.group(1))
            return int(time.time() - minute * 60) * 1000

        t = re.search(r'(\d+).*?天', tag)
        if t:
            day = t.group(1)
            return TimeHandler.getTimeOfNDayBefore(day)

        t = re.search(r'前天', tag)
        if t:
            return TimeHandler.getTimeOfNDayBefore(2)
        t = re.search(r'昨天', tag)
        if t:
            return TimeHandler.getTimeOfNDayBefore(1)

        t = re.search(r'今天', tag)
        if t:
            return TimeHandler.getTimeOfNDayBefore(0)

        t = re.search(r'刚刚', tag)
        if t:
            return int(time.time()) * 1000

        t = re.search(r'(\d+)月内', tag)
        if t:
            day = int(t.group(1)) * 30
            return TimeHandler.getTimeOfNDayBefore(day)

        t = re.search(r'(\d+)周内', tag)
        if t:
            day = int(t.group(1)) * 7
            return TimeHandler.getTimeOfNDayBefore(day)

        t = re.search(r'(\d+).*?day', tag)
        if t:
            day = t.group(1)
            return TimeHandler.getTimeOfNDayBefore(day)

        t = re.search(r'(\d+).*?hour', tag)
        if t:
            hour = int(t.group(1))
            return int(time.time() - hour * 3600) * 1000

        t = re.search(r'(\d+).*?minute', tag)
        if t:
            minute = int(t.group(1))
            return int(time.time() - minute * 60) * 1000

        t = re.search(r'(\d+)个月前', tag)
        if t:
            day = int(t.group(1)) * 30
            return TimeHandler.getTimeOfNDayBefore(day)

        raise Exception("not copy time pattern: {}".format(tag))


class System:
    @staticmethod
    def hostname():
        try:
            return os.uname()[1]
        except:
            pass

        try:
            with open('/etc/hostname') as f:
                return f.readline().strip()
        except:
            pass
        try:
            a = os.popen("hostname")
            return a.read().strip()
        except:
            pass
        return None

    @staticmethod
    def is_osx():
        return system() == 'Darwin'


def empty_str(s):
    return s is None or s == ''


def chained_regex(s, *regex):
    inp = [s]
    outarr = []
    retype = type(re.compile(''))
    for ri in regex:
        for ss in inp:
            if isinstance(ri, str) or isinstance(ri, unicode):
                m = re.findall(ri, ss)
            elif isinstance(ri, retype):  # assume ri is a compiled pattern
                m = ri.findall(ss)
            else:
                raise RuntimeError('invalid arg')
            if m:
                outarr.extend(m)
        if len(outarr) == 0:
            return []
        inp = outarr
        outarr = []
    return inp


def unique_list(arr, key_fun=None):
    if not isinstance(arr, list):
        return arr
    oarr = []
    _tmp_ = []
    func = (lambda a: a) if key_fun is None else key_fun
    for i in arr:
        c = func(i)
        if c not in _tmp_:
            _tmp_.append(c)
            oarr.append(i)
    return oarr


def sendmail(email, title, message, is_html=False):
    username = ''
    password = ''
    smtphost = ''
    smtpport = ''

    if isinstance(message, unicode):
        message = message.encode('utf-8')
    if isinstance(title, unicode):
        title = message.encode('utf-8')
    if is_html:
        msg = MIMEText(message, 'html', 'utf-8')
    else:
        msg = MIMEText(message, 'plain', 'utf-8')
    msg['Subject'] = Header(title, 'utf-8')
    msg['From'] = username
    if isinstance(email, list):
        msg['To'] = '; '.join(email)
        tolist = email
    else:
        msg['To'] = email
        tolist = [email]
    for i in range(0, len(tolist)):
        m = re.search('<([a-z0-9_@\-.]*)>\s*$', tolist[i], re.I)
        if m:
            tolist[i] = m.group(1)
    print "sending mail to", tolist
    print msg.as_string()
    s = smtplib.SMTP_SSL(smtphost, smtpport)
    s.login(username, password)
    s.sendmail(username, tolist, msg.as_string())
    s.quit()
