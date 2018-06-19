import random
import string

tags = ['h1','h2','img','script','iframe','div','span','link','p','pre','font','code','dd','center','a','object','textarea','em','canvas','button']

fp = open("test.html","w")

def RandomHtml(num):
    yield '<html><body>'
    yield RandomBody(num)
    yield '</body></html>'

def RandomBody(num):
    for i in range(int(num/len(tags))):
        for tag in tags:
            yield RandomSection(tag)

def RandomDomain():
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(5))+'.test'

def RandomSection(tag):
    if tag in ['img','script','iframe']:
        yield "<%s src=\"http://%s\">" % (tag, RandomDomain())
        yield "</%s>\n" % tag
    elif tag in ['link','a','iframe']:
        yield "<%s href=\"http://%s\">" % (tag, RandomDomain())
        yield "</%s>\n" % tag
    else:
        yield "<%s>" % tag
        yield RandomSentence()
        yield "</%s>" % tag
    sentences = random.randrange(1, 3)
    for _ in range(sentences):
         yield RandomSentence()

def RandomSentence():
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(5))

def save(generator):
    if isinstance(generator, str):
        fp.write(generator)
    else:
        for g in generator: save(g)

save(RandomHtml(4000))