import datetime, re, unicodedata
FIELDS=['id','imie','nazwisko','pesel','ulica','nr_budynku','nr_lokalu','kod_pocztowy','miejscowosc','kraj']
# Windows-1250 Polish letters misdecoded as Latin-1 control characters.
# Only these reversible signatures are repaired; valid alphabetic characters,
# punctuation, replacement glyphs and missing diacritics are never guessed.
NAME_ENCODING_FIXES={'\u008c':'Ś','\u009c':'ś','\u008f':'Ź','\u009f':'ź'}

def repair_name_encoding(value):
    return ''.join(NAME_ENCODING_FIXES.get(c,c) for c in value)

def encoding_note(p):
    repairs=p.get('_encoding_repairs',[])
    return 'Automatycznie naprawiono kodowanie: '+', '.join(repairs)+'.' if repairs else ''
ALIASES={
'id':['id','identyfikator','id_zrodlowe'], 'imie':['imie','name','firstname','first_name'],
'nazwisko':['nazwisko','surname','lastname','last_name'], 'pesel':['pesel','nrpesel','nr_pesel','nr pesel'],
'ulica':['ulica','street','adres.ulica'], 'nr_budynku':['nr_budynku','numer_budynku','buildingnumber','adres.numer_budynku','adres.nr_budynku'],
'nr_lokalu':['nr_lokalu','numer_lokalu','flatnumber','adres.numer_lokalu','adres.nr_lokalu'],
'kod_pocztowy':['kod_pocztowy','kod pocztowy','postalcode','adres.kod_pocztowy'],
'miejscowosc':['miejscowosc','miasto','city','adres.miejscowosc'], 'kraj':['kraj','countrycode','adres.kraj']}

def column_key(s):
    s=unicodedata.normalize('NFKD',s.casefold().replace('ł','l'))
    return ''.join(c for c in s if not unicodedata.combining(c)).strip()
def mapping_for(columns):return {f:next((c for c in columns if column_key(c) in names),'') for f,names in ALIASES.items()}
def flatten(obj,prefix=''):
    out={}
    for k,v in obj.items():
        key=prefix+str(k)
        if isinstance(v,dict):out.update(flatten(v,key+'.'))
        elif isinstance(v,(str,int,float)) or v is None:out[key]=v
        else:raise ValueError('Wartość kolumny nie może być tablicą ani wartością logiczną')
    return out

def pesel_valid(s):
    if not re.fullmatch('[0-9]{11}',s):return False
    if (10-sum(int(a)*b for a,b in zip(s[:10],[1,3,7,9,1,3,7,9,1,3]))%10)%10!=int(s[-1]):return False
    y,m,d=int(s[:2]),int(s[2:4]),int(s[4:6]); century={0:1900,1:2000,2:2100,3:2200,4:1800}.get(m//20)
    try:datetime.date(century+y,m%20,d);return True
    except (ValueError,TypeError):return False

def person(raw,mapping=None):
    m=mapping or {f:f for f in FIELDS}
    p={f:unicodedata.normalize('NFC',str(raw.get(m.get(f,''), '') or '')).strip() for f in FIELDS}
    repairs=[]
    for field in ['imie','nazwisko']:
        original=p[field]
        for c in dict.fromkeys(original):
            if c in NAME_ENCODING_FIXES:repairs.append(field+' U+'+f'{ord(c):04X}'+' → '+NAME_ENCODING_FIXES[c])
        p[field]=repair_name_encoding(original)
    if repairs:p['_encoding_repairs']=repairs
    errors=[]
    for f in ['id','pesel']:
        v=raw.get(m.get(f,''))
        if v is not None and not isinstance(v,str):errors.append(f'{f}: identyfikator musi być tekstem')
    for f,limit in [('imie',240),('nazwisko',300)]:
        if not 2<=len(p[f])<=limit or not all(c.isalpha() or c in " -’'" for c in p[f]):errors.append(f'{f}: wymagane co najmniej 2 litery; dopuszczalne spacje, łącznik i apostrof')
    for f,limit in [('ulica',512),('nr_budynku',128),('nr_lokalu',128),('kod_pocztowy',128),('miejscowosc',512)]:
        if len(p[f])>limit or any(ord(c)<32 for c in p[f]):errors.append(f'{f}: niedozwolona długość lub znak sterujący')
    if p['pesel']:
        if not pesel_valid(p['pesel']):errors.append('PESEL: nieprawidłowa suma kontrolna lub data urodzenia')
    else:
        for f in ['nr_budynku','kod_pocztowy','miejscowosc']:
            if not p[f]:errors.append(f'{f}: pole wymagane w metodzie adresowej')
        p['kraj']=(p['kraj'] or 'PL').upper()
        if p['kraj']=='PL' and not re.fullmatch('[0-9]{2}-[0-9]{3}',p['kod_pocztowy']):errors.append('Kod pocztowy: wymagany format 00-000')
        if not re.fullmatch('[A-Z]{2}',p['kraj']):errors.append('Kraj: kod ISO składający się z dwóch liter')
    return p,errors
