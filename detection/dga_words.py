"""Readable-name check: a label made only of common English/web words is not a generated domain.

Lexical DGA models score concatenated words ("clickherenow") as random. This is a small
curated list, English and web terms only; names in other languages are not recognised. Dictionary-word DGAs
(for example suppobox) are therefore also suppressed, a disclosed recall cost.
"""
from functools import lru_cache

WORDS = frozenset('''
a all and any app apps art ask auto award away back bad bank base best bet big bike bill bio bit blog blue body book
box boys brand bridge build business buy call camp car card care cars cash center chat check city class click clean
clear clip clips club cloud code coin cold college color come community company cool copy core cost course crazy
cross cyber daily dark data date day deal design desk digital direct doc docs doctor dog dollar domain down download
downloads drive drop early earth easy edge edit education email end energy engine event every expert extra
family fan fast file files film films final find fine fire first fish fit fix flash flat flow food for forum free
fresh from fun fund future game games garden gas gate gear get gift girl girls give global go gold good great green
group guide guys hair hand happy hard head health heart help here high hill home host hot hotel house how hub
image images in info insurance international internet job jobs join just key kid kids king
kitchen know land large last law learn legal life light like line link links list little live loan local lock
login look love low mail main make man many map market master match max media meet member men menu mind mini mobile
money more movie movies music my name net network new news next nice night no north note now number office old on
one online open our out page paid park partner party pay people phone photo photos pick pixel place plan play plus
point pool post power press price prime pro product project public pure quick radio rank rate read ready real
red rent report review rich ride right ring road rock room safe sale save school science search secure see sell
send server service shop show sign site sky small smart snap social soft software solar sound south space special
speed sport sports spot star start state station stock stop store story stream street studio style super sure
sweet system tag take talk tax team tech test text the time tip tips to today tool tools top tour
town toy track trade travel tree trip true trust try tube turn tv under unlimited up update upload us user van video
videos view vip visit voice wall want watch water way we web website week west white wide win wire wish with won
word work works world write yes you young your zone
'''.split())

MIN_WORD = 2


@lru_cache(maxsize=4096)
def _segments(text):
    if not text:
        return True
    return any(text[:i] in WORDS and _segments(text[i:]) for i in range(MIN_WORD, len(text) + 1))


def is_readable_label(label):
    """True if every hyphen-separated part splits fully into listed words and there are 2+ words overall."""
    parts = [p for p in (label or '').lower().split('-') if p]
    if not parts or any(not p.isalpha() for p in parts):
        return False
    if not all(_segments(p) for p in parts):
        return False
    return len(parts) >= 2 or not (label.lower() in WORDS)
