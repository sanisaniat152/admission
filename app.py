import os, sqlite3, random, secrets, time, re, json, html
from flask import Flask, request, jsonify, g
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
DB_PATH = "admission.db"

# ---------- SECURITY: Rate Limit - 1 min e 10 bar er besi try korle block ----------
RATE = {}
def check_rate(ip):
    now = time.time()
    if ip not in RATE: RATE[ip] = []
    RATE[ip] = [t for t in RATE[ip] if now - t < 60]
    if len(RATE[ip]) >= 20:
        return False
    RATE[ip].append(now)
    return True

@app.after_request
def security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    resp.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline';"
    resp.headers['Referrer-Policy'] = 'no-referrer'
    return resp

# ---------- EIIN DATABASE ----------
EIIN_DB = {
"108351":"Dhaka College, Dhaka","108274":"Notre Dame College, Dhaka","108258":"Holy Cross College, Dhaka",
"108259":"St. Joseph Higher Secondary School, Dhaka","108355":"Dhaka Residential Model College",
"108352":"Ideal School & College, Dhaka","108353":"Viqarunnisa Noon School & College, Dhaka",
"108357":"Adamjee Cantonment College, Dhaka","108356":"Rajuk Uttara Model College, Dhaka",
"108572":"Chittagong College, Chattogram","104112":"Chittagong Cantonment Public College",
"130454":"Rajshahi College, Rajshahi","126490":"Rajshahi Govt. City College",
"117118":"Khulna Public College, Khulna","120123":"Barishal Govt. B M College",
"100011":"Sylhet Govt. College, Sylhet","130017":"Sylhet MC College",
"128123":"Mymensingh Ananda Mohan College","111920":"Rangpur Govt. College",
"127456":"Bogura Govt. Azizul Haque College","115234":"Cumilla Victoria Govt. College",
"108111":"Dhaka City College","108222":"Bir Shrestha Munshi Abdur Rouf College, Dhaka",
"108444":"Milestone College, Dhaka","108666":"Cambrian School & College, Dhaka",
"109001":"Feni Govt. College","109002":"Noakhali Govt. College",
"131002":"Carmichael College, Rangpur","132015":"Pabna Govt. Edward College",
"132001":"Cantonment Public School & College, Saidpur","109003":"Lakshmipur Govt. College",
}

# ---------- QUESTION BANK - SERVER E THAKBE, BROWSER E ANSWER JABE NA ----------
QUESTIONS = {
"Biology": [
{"q":"Which organelle is the powerhouse of the cell?","bn":"কোষের শক্তিঘর কোন অঙ্গাণুকে বলা হয়?","o":["Nucleus","Mitochondria","Ribosome","Golgi Body"],"bn_o":["নিউক্লিয়াস","মাইটোকন্ড্রিয়া","রাইবোসোম","গলগি বডি"],"a":1},
{"q":"What is the functional unit of the kidney?","bn":"বৃক্কের কার্যকরী একক কোনটি?","o":["Neuron","Nephron","Alveolus","Glomerulus"],"bn_o":["নিউরন","নেফ্রন","অ্যালভিওলাস","গ্লোমেরুলাস"],"a":1},
{"q":"Which blood group is the universal donor?","bn":"সর্বজনীন দাতা রক্তের গ্রুপ কোনটি?","o":["AB+","AB-","O+","O-"],"bn_o":["এবি+","এবি-","ও+","ও-"],"a":3},
{"q":"Photosynthesis occurs in which organelle?","bn":"সালোকসংশ্লেষণ কোথায় ঘটে?","o":["Mitochondria","Chloroplast","Vacuole","Nucleus"],"bn_o":["মাইটোকন্ড্রিয়া","ক্লোরোপ্লাস্ট","ভ্যাকুওল","নিউক্লিয়াস"],"a":1},
{"q":"Which hormone controls blood sugar?","bn":"রক্তে শর্করা নিয়ন্ত্রণ করে কোন হরমোন?","o":["Adrenaline","Insulin","Thyroxine","Testosterone"],"bn_o":["অ্যাড্রেনালিন","ইনসুলিন","থাইরক্সিন","টেস্টোস্টেরন"],"a":1},
{"q":"How many chambers are in the human heart?","bn":"মানুষের হৃদপিণ্ডে কয়টি প্রকোষ্ঠ?","o":["2","3","4","5"],"bn_o":["২টি","৩টি","৪টি","৫টি"],"a":2},
{"q":"Which vitamin is produced in skin by sunlight?","bn":"সূর্যের আলোতে ত্বকে কোন ভিটামিন তৈরি হয়?","o":["Vitamin A","Vitamin B","Vitamin C","Vitamin D"],"bn_o":["ভিটামিন এ","ভিটামিন বি","ভিটামিন সি","ভিটামিন ডি"],"a":3},
{"q":"What is the largest organ of the human body?","bn":"মানবদেহের সবচেয়ে বড় অঙ্গ কোনটি?","o":["Heart","Liver","Skin","Lung"],"bn_o":["হৃদপিণ্ড","যকৃৎ","ত্বক","ফুসফুস"],"a":2},
{"q":"Which blood cells carry oxygen?","bn":"কোন রক্তকণিকা অক্সিজেন বহন করে?","o":["WBC","RBC","Platelet","Plasma"],"bn_o":["শ্বেত রক্তকণিকা","লোহিত রক্তকণিকা","অণুচক্রিকা","প্লাজমা"],"a":1},
{"q":"What is the scientific name of human?","bn":"মানুষের বৈজ্ঞানিক নাম কী?","o":["Homo erectus","Homo sapiens","Pan troglodytes","Australopithecus"],"bn_o":["হোমো ইরেকটাস","হোমো স্যাপিয়েন্স","প্যান ট্রোগ্লোডাইটস","অস্ট্রালোপিথেকাস"],"a":1},
],
"Physics": [
{"q":"What is the SI unit of force?","bn":"বলের এসআই একক কোনটি?","o":["Joule","Newton","Watt","Pascal"],"bn_o":["জুল","নিউটন","ওয়াট","প্যাসকেল"],"a":1},
{"q":"What is the value of g?","bn":"অভিকর্ষজ ত্বরণ g এর মান কত?","o":["9.8 m/s²","10.8 m/s²","8.9 m/s²","9.2 m/s²"],"bn_o":["৯.৮ মি/সে²","১০.৮ মি/সে²","৮.৯ মি/সে²","৯.২ মি/সে²"],"a":0},
{"q":"F = ma is which law?","bn":"F=ma কোন সূত্র?","o":["Newton's 1st Law","Newton's 2nd Law","Newton's 3rd Law","Ohm's Law"],"bn_o":["নিউটনের ১ম সূত্র","নিউটনের ২য় সূত্র","নিউটনের ৩য় সূত্র","ওহমের সূত্র"],"a":1},
{"q":"What is the unit of electric current?","bn":"বিদ্যুৎ প্রবাহের একক কোনটি?","o":["Volt","Ohm","Ampere","Watt"],"bn_o":["ভোল্ট","ওহম","অ্যাম্পিয়ার","ওয়াট"],"a":2},
{"q":"What is the speed of light in vacuum?","bn":"শূন্য মাধ্যমে আলোর বেগ কত?","o":["3×10⁸ m/s","3×10⁶ m/s","3×10⁵ m/s","3×10⁷ m/s"],"bn_o":["৩×১০⁸ মি/সে","৩×১০⁶ মি/সে","৩×১০⁵ মি/সে","৩×১০⁷ মি/সে"],"a":0},
{"q":"What is Ohm's Law?","bn":"ওহমের সূত্র কোনটি?","o":["V=IR","V=I/R","V=I²R","V=R/I"],"bn_o":["V=IR","V=I/R","V=I²R","V=R/I"],"a":0},
{"q":"Which color has the maximum wavelength?","bn":"কোন রঙের তরঙ্গদৈর্ঘ্য সবচেয়ে বেশি?","o":["Violet","Blue","Green","Red"],"bn_o":["বেগুনি","নীল","সবুজ","লাল"],"a":3},
{"q":"What is the unit of power?","bn":"ক্ষমতার একক কোনটি?","o":["Joule","Watt","Newton","Volt"],"bn_o":["জুল","ওয়াট","নিউটন","ভোল্ট"],"a":1},
{"q":"Work done = ?","bn":"কৃতকাজ = ?","o":["Force × Distance","Force / Distance","Mass × Velocity","Force × Time"],"bn_o":["বল × সরণ","বল / সরণ","ভর × বেগ","বল × সময়"],"a":0},
{"q":"Which is a vector quantity?","bn":"কোনটি ভেক্টর রাশি?","o":["Mass","Speed","Velocity","Distance"],"bn_o":["ভর","দ্রুতি","বেগ","দূরত্ব"],"a":2},
],
"Chemistry": [
{"q":"What is the atomic number of carbon?","bn":"কার্বনের পারমাণবিক সংখ্যা কত?","o":["6","8","12","14"],"bn_o":["৬","৮","১২","১৪"],"a":0},
{"q":"What is the pH of a neutral solution?","bn":"নিরপেক্ষ দ্রবণের pH কত?","o":["0","7","14","1"],"bn_o":["০","৭","১৪","১"],"a":1},
{"q":"What is the formula of sulphuric acid?","bn":"সালফিউরিক অ্যাসিডের সংকেত কোনটি?","o":["HCl","HNO3","H2SO4","CH3COOH"],"bn_o":["HCl","HNO3","H2SO4","CH3COOH"],"a":2},
{"q":"Which gas is used in balloons?","bn":"বেলুনে কোন গ্যাস ব্যবহার করা হয়?","o":["Oxygen","Helium","Nitrogen","CO2"],"bn_o":["অক্সিজেন","হিলিয়াম","নাইট্রোজেন","কার্বন ডাই-অক্সাইড"],"a":1},
{"q":"What is the symbol of sodium?","bn":"সোডিয়ামের প্রতীক কোনটি?","o":["So","Na","S","N"],"bn_o":["So","Na","S","N"],"a":1},
{"q":"Which is the lightest element?","bn":"সবচেয়ে হালকা মৌল কোনটি?","o":["Helium","Hydrogen","Oxygen","Lithium"],"bn_o":["হিলিয়াম","হাইড্রোজেন","অক্সিজেন","লিথিয়াম"],"a":1},
{"q":"What is Avogadro's number?","bn":"অ্যাভোগাড্রো সংখ্যা কত?","o":["6.02×10²³","3.02×10²³","1.6×10⁻¹⁹","9.11×10⁻³¹"],"bn_o":["৬.০২×১০²³","৩.০২×১০²³","১.৬×১০⁻¹⁹","৯.১১×১০⁻³¹"],"a":0},
{"q":"What is the common name of NaHCO3?","bn":"NaHCO3 এর সাধারণ নাম কী?","o":["Washing Soda","Baking Soda","Caustic Soda","Bleaching Powder"],"bn_o":["ওয়াশিং সোডা","বেকিং সোডা","কস্টিক সোডা","ব্লিচিং পাউডার"],"a":1},
{"q":"Which acid is in vinegar?","bn":"ভিনেগারে কোন অ্যাসিড থাকে?","o":["Citric Acid","Acetic Acid","Lactic Acid","Formic Acid"],"bn_o":["সাইট্রিক অ্যাসিড","অ্যাসিটিক অ্যাসিড","ল্যাকটিক অ্যাসিড","ফরমিক অ্যাসিড"],"a":1},
{"q":"What is the pH of blood?","bn":"রক্তের pH কত?","o":["6.4","7.0","7.4","8.4"],"bn_o":["৬.৪","৭.০","৭.৪","৮.৪"],"a":2},
],
"Higher Math": [
{"q":"What is the derivative of x²?","bn":"x² এর অন্তরজ কত?","o":["x","2x","x²","2"],"bn_o":["x","2x","x²","2"],"a":1},
{"q":"What is ∫ 1/x dx ?","bn":"∫ 1/x dx = কত?","o":["ln x + C","x + C","1/x² + C","e^x + C"],"bn_o":["ln x + C","x + C","1/x² + C","e^x + C"],"a":0},
{"q":"What is sin²θ + cos²θ ?","bn":"sin²θ + cos²θ = কত?","o":["0","1","2","tan θ"],"bn_o":["০","১","২","tan θ"],"a":1},
{"q":"What is the value of sin 90°?","bn":"sin 90° এর মান কত?","o":["0","1","1/2","√3/2"],"bn_o":["০","১","১/২","√৩/২"],"a":1},
{"q":"What is log₂ 8 ?","bn":"log₂ 8 = কত?","o":["2","3","4","8"],"bn_o":["২","৩","৪","৮"],"a":1},
{"q":"What is i² ?","bn":"i² = কত?","o":["1","-1","0","i"],"bn_o":["১","-১","০","i"],"a":1},
{"q":"What is the slope of y=2x+3?","bn":"y=2x+3 এর ঢাল কত?","o":["2","3","1","5"],"bn_o":["২","৩","১","৫"],"a":0},
{"q":"What is 5! ?","bn":"৫! = কত?","o":["20","60","120","100"],"bn_o":["২০","৬০","১২০","১০০"],"a":2},
{"q":"What is the integral of cos x?","bn":"cos x এর যোগজ কত?","o":["sin x + C","-sin x + C","cos x + C","-cos x + C"],"bn_o":["sin x + C","-sin x + C","cos x + C","-cos x + C"],"a":0},
{"q":"What is tan 45°?","bn":"tan 45° = কত?","o":["0","1","√3","∞"],"bn_o":["০","১","√৩","∞"],"a":1},
],
"English": [
{"q":"Choose the correct spelling:","bn":"সঠিক বানান কোনটি?","o":["Accomodation","Accommodation","Acomodation","Accomodatin"],"bn_o":["Accomodation","Accommodation","Acomodation","Accomodatin"],"a":1},
{"q":"What is the synonym of 'Happy'?","bn":"'Happy' এর সমার্থক শব্দ কোনটি?","o":["Sad","Joyful","Angry","Lazy"],"bn_o":["দুঃখিত","আনন্দিত","রাগান্বিত","অলস"],"a":1},
{"q":"What is the antonym of 'Ancient'?","bn":"'Ancient' এর বিপরীত শব্দ কোনটি?","o":["Old","Modern","Past","Historic"],"bn_o":["পুরাতন","আধুনিক","অতীত","ঐতিহাসিক"],"a":1},
{"q":"He ___ to school daily.","bn":"He ___ to school daily.","o":["go","goes","going","gone"],"bn_o":["go","goes","going","gone"],"a":1},
{"q":"What is the passive form of 'He writes a letter'?","bn":"'He writes a letter' এর Passive কোনটি?","o":["A letter is written by him","A letter was written by him","A letter is writing by him","A letter is wrote by him"],"bn_o":["A letter is written by him","A letter was written by him","A letter is writing by him","A letter is wrote by him"],"a":0},
{"q":"Which one is a noun?","bn":"কোনটি Noun?","o":["Quickly","Happiness","Run","Beautiful"],"bn_o":["Quickly","Happiness","Run","Beautiful"],"a":1},
{"q":"What is the plural of 'Child'?","bn":"'Child' এর Plural কোনটি?","o":["Childs","Children","Childes","Childrens"],"bn_o":["Childs","Children","Childes","Childrens"],"a":1},
{"q":"He is good ___ English.","bn":"He is good ___ English.","o":["in","at","for","to"],"bn_o":["in","at","for","to"],"a":1},
{"q":"What is the synonym of 'Brave'?","bn":"'Brave' এর সমার্থক শব্দ কোনটি?","o":["Coward","Fearless","Weak","Shy"],"bn_o":["কাপুরুষ","নির্ভীক","দুর্বল","লাজুক"],"a":1},
{"q":"What do you call one who can use both hands?","bn":"যে দুই হাত ব্যবহার করতে পারে তাকে কী বলে?","o":["Versatile","Ambidextrous","Ambivalent","Ambiguous"],"bn_o":["Versatile","Ambidextrous","Ambivalent","Ambiguous"],"a":1},
],
"Bangla": [
{"q":"বাংলা ভাষার জনক কে?","bn":"বাংলা ভাষার জনক কে?","o":["রবীন্দ্রনাথ ঠাকুর","ঈশ্বরচন্দ্র বিদ্যাসাগর","কাজী নজরুল ইসলাম","মাইকেল মধুসূদন দত্ত"],"bn_o":["রবীন্দ্রনাথ ঠাকুর","ঈশ্বরচন্দ্র বিদ্যাসাগর","কাজী নজরুল ইসলাম","মাইকেল মধুসূদন দত্ত"],"a":1},
{"q":"'সূর্য' এর সমার্থক শব্দ কোনটি?","bn":"'সূর্য' এর সমার্থক শব্দ কোনটি?","o":["চন্দ্র","রবি","তারা","আকাশ"],"bn_o":["চন্দ্র","রবি","তারা","আকাশ"],"a":1},
{"q":"বাংলা নববর্ষ কবে পালিত হয়?","bn":"বাংলা নববর্ষ কবে পালিত হয়?","o":["১৪ এপ্রিল","১লা বৈশাখ","১লা জানুয়ারি","১৬ ডিসেম্বর"],"bn_o":["১৪ এপ্রিল","১লা বৈশাখ","১লা জানুয়ারি","১৬ ডিসেম্বর"],"a":1},
{"q":"'অন্ধকার' এর বিপরীত শব্দ?","bn":"'অন্ধকার' এর বিপরীত শব্দ?","o":["কালো","আলো","রাত","ছায়া"],"bn_o":["কালো","আলো","রাত","ছায়া"],"a":1},
{"q":"গীতাঞ্জলি কে লিখেছেন?","bn":"গীতাঞ্জলি কে লিখেছেন?","o":["নজরুল","রবীন্দ্রনাথ ঠাকুর","জসীমউদ্দীন","সুকান্ত"],"bn_o":["নজরুল","রবীন্দ্রনাথ ঠাকুর","জসীমউদ্দীন","সুকান্ত"],"a":1},
{"q":"বাংলা ভাষায় মোট বর্ণ কয়টি?","bn":"বাংলা ভাষায় মোট বর্ণ কয়টি?","o":["৪৯টি","৫০টি","৫১টি","৫২টি"],"bn_o":["৪৯টি","৫০টি","৫১টি","৫২টি"],"a":1},
{"q":"জাতীয় সংগীতের রচয়িতা কে?","bn":"জাতীয় সংগীতের রচয়িতা কে?","o":["কাজী নজরুল","রবীন্দ্রনাথ ঠাকুর","জসীমউদ্দীন","সুফিয়া কামাল"],"bn_o":["কাজী নজরুল","রবীন্দ্রনাথ ঠাকুর","জসীমউদ্দীন","সুফিয়া কামাল"],"a":1},
{"q":"বাংলা সাহিত্যের প্রথম উপন্যাস কোনটি?","bn":"বাংলা সাহিত্যের প্রথম উপন্যাস কোনটি?","o":["দুর্গেশনন্দিনী","আলালের ঘরের দুলাল","কপালকুণ্ডলা","বিষবৃক্ষ"],"bn_o":["দুর্গেশনন্দিনী","আলালের ঘরের দুলাল","কপালকুণ্ডলা","বিষবৃক্ষ"],"a":1},
],
"GK": [
{"q":"What is the capital of Bangladesh?","bn":"বাংলাদেশের রাজধানী কোনটি?","o":["Chittagong","Dhaka","Sylhet","Khulna"],"bn_o":["চট্টগ্রাম","ঢাকা","সিলেট","খুলনা"],"a":1},
{"q":"Which is the largest country by area?","bn":"আয়তনে সবচেয়ে বড় দেশ কোনটি?","o":["China","USA","Canada","Russia"],"bn_o":["চীন","যুক্তরাষ্ট্র","কানাডা","রাশিয়া"],"a":3},
{"q":"Which is the longest river in the world?","bn":"বিশ্বের দীর্ঘতম নদী কোনটি?","o":["Amazon","Nile","Yangtze","Ganga"],"bn_o":["আমাজন","নীল","ইয়াংসি","গঙ্গা"],"a":1},
{"q":"Which ocean is the largest?","bn":"সবচেয়ে বড় মহাসাগর কোনটি?","o":["Atlantic","Indian","Arctic","Pacific"],"bn_o":["আটলান্টিক","ভারত","আর্কটিক","প্রশান্ত"],"a":3},
{"q":"How many continents are there?","bn":"পৃথিবীতে কয়টি মহাদেশ?","o":["5","6","7","8"],"bn_o":["৫টি","৬টি","৭টি","৮টি"],"a":2},
{"q":"In which country is the Eiffel Tower?","bn":"আইফেল টাওয়ার কোন দেশে?","o":["Italy","Germany","France","Spain"],"bn_o":["ইতালি","জার্মানি","ফ্রান্স","স্পেন"],"a":2},
{"q":"What is the currency of Japan?","bn":"জাপানের মুদ্রা কোনটি?","o":["Won","Yuan","Yen","Ringgit"],"bn_o":["ওন","ইউয়ান","ইয়েন","রিঙ্গিত"],"a":2},
{"q":"In which year did Bangladesh become independent?","bn":"বাংলাদেশ কত সালে স্বাধীন হয়?","o":["1947","1952","1971","1972"],"bn_o":["১৯৪৭","১৯৫২","১৯৭১","১৯৭২"],"a":2},
{"q":"In which year did the Language Movement happen?","bn":"ভাষা আন্দোলন কত সালে হয়?","o":["1947","1952","1969","1971"],"bn_o":["১৯৪৭","১৯৫২","১৯৬৯","১৯৭১"],"a":1},
{"q":"Who was the first President of the USA?","bn":"যুক্তরাষ্ট্রের প্রথম প্রেসিডেন্ট কে?","o":["Abraham Lincoln","George Washington","Thomas Jefferson","John Adams"],"bn_o":["আব্রাহাম লিংকন","জর্জ ওয়াশিংটন","থমাস জেফারসন","জন অ্যাডামস"],"a":1},
],
}

EXAM_DIST = {
"DU - A Unit": {"Physics":8,"Chemistry":8,"Higher Math":6,"Biology":6,"English":6,"Bangla":6},
"Medical": {"Biology":8,"Chemistry":8,"Physics":8,"English":8,"GK":8},
"BUET": {"Physics":10,"Chemistry":10,"Higher Math":10},
"JU - D Unit": {"Biology":8,"Chemistry":8,"Physics":8,"Bangla":8,"English":8},
"CU - A Unit": {"Biology":8,"Chemistry":8,"Physics":8,"Higher Math":8,"Bangla":4,"English":4},
"Mixed Mock": {"Physics":6,"Chemistry":6,"Higher Math":6,"Biology":6,"English":5,"Bangla":5,"GK":6},
}

# Active exam - server e thakbe, kew change korte parbe na
ACTIVE = {}

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, eiin TEXT, college TEXT, class_name TEXT, roll TEXT, reg_no TEXT UNIQUE, roll_no TEXT UNIQUE, created_at TEXT)")
    db.execute("CREATE TABLE IF NOT EXISTS exams (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, reg_no TEXT, name TEXT, eiin TEXT, college TEXT, exam_type TEXT, score REAL, correct INTEGER, wrong INTEGER, skipped INTEGER, questions TEXT, created_at TEXT)")
    db.commit(); db.close()
init_db()

def clean_input(s, max_len=50):
    if not isinstance(s, str): return ""
    s = html.escape(s.strip())[:max_len]
    return s

@app.route('/')
def home():
    return FRONTEND_HTML

@app.route('/api/check-eiin')
def check_eiin():
    if not check_rate(request.remote_addr): return jsonify({"ok":False,"msg":"Too many requests. Wait 1 min."}), 429
    eiin = request.args.get('eiin','').strip()
    if len(eiin)!=6 or not eiin.isdigit():
        return jsonify({"ok":False,"msg":"EIIN must be 6 digits!"})
    if eiin in EIIN_DB:
        return jsonify({"ok":True,"college":EIIN_DB[eiin],"msg":"✅ Correct EIIN - "+EIIN_DB[eiin]})
    return jsonify({"ok":False,"msg":"❌ Wrong EIIN! This EIIN is not in our list."})

@app.route('/api/register', methods=['POST'])
def register():
    if not check_rate(request.remote_addr): return jsonify({"ok":False,"msg":"Too many requests"}),429
    d = request.json or {}
    name = clean_input(d.get('name',''), 40)
    eiin = str(d.get('eiin','')).strip()
    class_name = clean_input(d.get('class_name',''), 20)
    roll = clean_input(d.get('roll',''), 20)
    # Validation - hack check
    if not re.match(r"^[A-Za-z\u0980-\u09FF .'-]{3,40}$", name):
        return jsonify({"ok":False,"msg":"Please enter a valid name (3-40 letters)."}),400
    if eiin not in EIIN_DB:
        return jsonify({"ok":False,"msg":"Wrong EIIN!"}),400
    if not re.match(r"^[A-Za-z0-9-]{1,20}$", roll):
        return jsonify({"ok":False,"msg":"Invalid Roll."}),400
    college = EIIN_DB[eiin]
    reg_no = f"REG-2026-{random.randint(1000,9999)}"
    roll_no = f"ROLL-{random.randint(10000,99999)}"
    db = get_db()
    cur = db.execute("SELECT * FROM users WHERE name=? AND eiin=? AND roll=?", (name,eiin,roll)).fetchone()
    if cur:
        db.close(); return jsonify({"ok":True,"user":dict(cur)})
    db.execute("INSERT INTO users (name,eiin,college,class_name,roll,reg_no,roll_no,created_at) VALUES (?,?,?,?,?,?,?,?)",
        (name,eiin,college,class_name,roll,reg_no,roll_no,datetime.now().isoformat()))
    db.commit()
    cur = db.execute("SELECT * FROM users WHERE reg_no=?", (reg_no,)).fetchone()
    db.close()
    return jsonify({"ok":True,"user":dict(cur)})

@app.route('/api/start', methods=['POST'])
def start_exam():
    d = request.json or {}
    exam_type = clean_input(d.get('exam_type',''), 30)
    reg_no = clean_input(d.get('reg_no',''), 30)
    if exam_type not in EXAM_DIST:
        return jsonify({"ok":False,"msg":"Invalid exam"}),400
    # Server e question banano - answer chara pathano hobe
    pool = []
    for sub, cnt in EXAM_DIST[exam_type].items():
        arr = QUESTIONS.get(sub, [])[:]
        random.shuffle(arr)
        for q in arr[:cnt]:
            pool.append({"cat":sub,"q":q["q"],"bn":q["bn"],"o":q["o"],"bn_o":q["bn_o"]})
    random.shuffle(pool)
    token = secrets.token_hex(16)
    # Asol answer server e save rakha
    answers = []
    # Pool er order onujayi asol answer khuje ber kora
    for item in pool:
        # Original theke match kora
        found = None
        for qq in QUESTIONS[item["cat"]]:
            if qq["q"]==item["q"]:
                found = qq["a"]; break
        answers.append(found)
    ACTIVE[token] = {"answers":answers,"questions":pool,"exam_type":exam_type,"reg_no":reg_no,"start":time.time(),"submitted":False}
    return jsonify({"ok":True,"token":token,"questions":pool,"time":45*60})

@app.route('/api/submit', methods=['POST'])
def submit():
    d = request.json or {}
    token = str(d.get('token',''))[:50]
    if token not in ACTIVE:
        return jsonify({"ok":False,"msg":"Session expired. Please start again."}),400
    sess = ACTIVE[token]
    if sess["submitted"]:
        return jsonify({"ok":False,"msg":"Already submitted! You cannot submit twice."}),400
    # Time check - server time diye - 45 min + 2 min extra
    if time.time() - sess["start"] > 47*60:
        return jsonify({"ok":False,"msg":"Time over!"}),400
    user_answers = d.get('answers',[])
    if not isinstance(user_answers, list) or len(user_answers)!=len(sess["answers"]):
        return jsonify({"ok":False,"msg":"Invalid answers"}),400
    # Server e check - browser er kotha bissas kora hobe na
    correct=wrong=skipped=0
    detailed=[]
    for i, ans in enumerate(sess["answers"]):
        ua = user_answers[i]
        if not isinstance(ua, int) or ua<-1 or ua>3:
            ua=-1
        q = sess["questions"][i]
        if ua==-1: skipped+=1
        elif ua==ans: correct+=1
        else: wrong+=1
        detailed.append({"q":q["q"],"bn":q["bn"],"cat":q["cat"],"options":q["o"],"bn_options":q["bn_o"],"correct":ans,"selected":ua})
    score = round(correct - wrong*0.25, 2)
    sess["submitted"]=True
    # User info
    db=get_db()
    u = db.execute("SELECT * FROM users WHERE reg_no=?", (sess["reg_no"],)).fetchone()
    if u:
        db.execute("INSERT INTO exams (user_id,reg_no,name,eiin,college,exam_type,score,correct,wrong,skipped,questions,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (u["id"],u["reg_no"],u["name"],u["eiin"],u["college"],sess["exam_type"],score,correct,wrong,skipped,json.dumps(detailed),datetime.now().isoformat()))
        db.commit()
    db.close()
    return jsonify({"ok":True,"score":score,"correct":correct,"wrong":wrong,"skipped":skipped,"detailed":detailed})

@app.route('/api/leaderboard')
def leaderboard():
    exam=request.args.get('exam','ALL')
    db=get_db()
    q="SELECT * FROM exams WHERE created_at >= ?"
    params=[(datetime.now()-timedelta(days=7)).isoformat()]
    if exam!='ALL':
        q+=" AND exam_type LIKE ?"; params.append(f"%{exam}%")
    q+=" ORDER BY score DESC LIMIT 100"
    rows=db.execute(q, params).fetchall(); db.close()
    seen={}; out=[]
    for r in rows:
        if r['reg_no'] not in seen:
            seen[r['reg_no']]=True; out.append(dict(r))
    for i,r in enumerate(out): r['rank']=i+1
    return jsonify(out)

@app.route('/api/my-history')
def my_history():
    reg=clean_input(request.args.get('reg',''),30)
    db=get_db()
    rows=db.execute("SELECT * FROM exams WHERE reg_no=? ORDER BY created_at DESC LIMIT 50", (reg,)).fetchall(); db.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/stats')
def stats():
    db=get_db()
    total=db.execute("SELECT COUNT(*) c FROM exams").fetchone()['c']
    users=db.execute("SELECT COUNT(*) c FROM users").fetchone()['c']
    db.close(); return jsonify({"total_exams":total,"total_users":users})

FRONTEND_HTML = """
<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Varsity Admission - Secure</title>
<style>*{box-sizing:border-box}body{margin:0;background:#0b0f1a;color:white;font-family:'Segoe UI',sans-serif;padding:12px}h1{text-align:center;color:#ffcc00;font-size:26px}.card{max-width:580px;margin:12px auto;background:#1a1e30;padding:16px;border-radius:18px;border:1px solid #333}input,select{width:100%;padding:13px;border-radius:12px;border:1px solid #444;background:#222;color:white;font-size:15px;margin:7px 0}.submit{width:100%;padding:14px;background:#ffcc00;border:none;border-radius:12px;font-weight:bold;font-size:16px;margin-top:10px;cursor:pointer}.lang-btn{padding:10px 22px;border:none;border-radius:20px;font-weight:bold;cursor:pointer;font-size:15px}.lang-btn.active{background:#ffcc00;color:#111}.lang-btn.inactive{background:#333;color:white}.lang-bar{display:flex;justify-content:center;gap:10px;margin:10px 0;position:sticky;top:0;z-index:10;background:#0b0f1a;padding:8px}.exam-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}.exam{padding:15px;border-radius:16px;cursor:pointer;font-weight:bold;text-align:center}.opt{padding:12px;background:#2a2a4a;border-radius:12px;margin:8px 0;cursor:pointer;border:2px solid transparent}.opt.selected{border-color:#ffcc00;background:#3a3a1a}.opt.correct{background:#00c853!important}.opt.wrong{background:#d50000!important}.opt.locked{cursor:not-allowed}.palette{display:grid;grid-template-columns:repeat(10,1fr);gap:5px;margin:10px 0}.pal{padding:8px 0;text-align:center;border-radius:8px;background:#333;cursor:pointer;font-size:12px}.pal.done{background:#00c853}.pal.wrong{background:#d50000}.pal.current{border:2px solid #ffcc00}.rank-item{display:flex;justify-content:space-between;background:#2a2a4a;padding:10px;border-radius:10px;margin:6px 0;font-size:13px}.rank1{background:linear-gradient(90deg,#ffcc00,#ff6d00);color:#111;font-weight:bold}.merit{text-align:center;background:linear-gradient(135deg,#ffcc00,#ff6d00);color:#111;padding:20px;border-radius:18px;max-width:580px;margin:12px auto}.tab{display:flex;gap:6px;flex-wrap:wrap;justify-content:center;margin:10px 0}.tab button{padding:8px 14px;border:none;border-radius:20px;cursor:pointer;font-weight:bold;background:#333;color:white}.tab button.active{background:#ffcc00;color:#111}</style></head><body>
<div class="lang-bar"><button class="lang-btn" id="btnBn" onclick="setLang(true)">বাংলা</button><button class="lang-btn" id="btnEn" onclick="setLang(false)">ENGLISH</button></div>
<h1 id="mainTitle">🎓 VARSITY ADMISSION - SECURE</h1><p style="text-align:center;color:#aaa;font-size:12px" id="subTitle">Secure Exam - Answers are checked on server, no one can hack</p>
<div id="loginDiv"><div class="card"><h2 style="text-align:center" id="loginTitle">📝 Login / Registration</h2><label id="lName">Your Full Name</label><input id="nameInput" placeholder="Rahim Uddin"><label id="lEIIN">College EIIN Number (6 Digits)</label><input id="eiinInput" placeholder="e.g. 108351" maxlength="6" oninput="checkEIINLive()"><div id="eiinMsg" style="font-size:13px;min-height:20px"></div><div id="collegeShow" style="background:#1a5c2a;padding:10px;border-radius:10px;display:none"></div><label id="lClass">Class</label><select id="classInput"><option>Class 12</option><option>Class 11</option><option>HSC Pass</option></select><label id="lRoll">Class Roll</label><input id="rollInput" placeholder="e.g. 101"><button class="submit" id="loginBtn" onclick="doLogin()">✅ LOGIN & GET REG NO</button><p style="font-size:12px;color:#aaa;text-align:center" id="loginHint">EIIN is your college code. Wrong EIIN will not allow login. Example: Dhaka College = 108351</p></div></div>
<div id="mainApp" style="display:none"><div class="card" style="text-align:center;background:linear-gradient(135deg,#1a3a8a,#1a5c2a)"><div id="welcomeTxt">Welcome!</div><div style="margin:8px 0"><span id="regTxt">Reg No:</span> <b id="showReg" style="color:#ffcc00"></b> | <span id="rollTxt">Roll No:</span> <b id="showRoll" style="color:#00e5ff"></b><br><span id="collegeTxt2"></span></div></div>
<div style="max-width:580px;margin:auto;display:flex;gap:8px"><button class="submit" style="flex:1" onclick="showHome()" id="bHome">🏠 HOME</button><button class="submit" style="flex:1;background:#00e5ff" onclick="showRanking()" id="bRank">🏆 RANKING</button><button class="submit" style="flex:1;background:#00c853;color:white" onclick="showMy()" id="bMy">📊 MY WEEK</button></div>
<div id="homeDiv"><div class="card"><b id="chooseTxt">Which University Exam Will You Take?</b><div class="exam-grid" id="exams"></div></div><div class="card"><b>🔴 Live Stats</b><p id="liveStats"></p></div></div>
<div id="rankDiv" style="display:none"><div class="card"><b id="rankTitle">🏆 Weekly Ranking - Everyone Can See</b><div class="tab" id="rankTabs"><button onclick="loadRank('ALL')" class="active">ALL</button><button onclick="loadRank('DU')">DU</button><button onclick="loadRank('Medical')">MEDICAL</button><button onclick="loadRank('BUET')">BUET</button><button onclick="loadRank('JU')">JU</button><button onclick="loadRank('CU')">CU</button><button onclick="loadRank('Mock')">MOCK</button></div><p style="font-size:12px;color:#aaa">Last 7 days - Best score per student</p><div id="rankList"></div></div></div>
<div id="myDiv" style="display:none"><div class="card"><b id="myTitle">📊 My This Week - Last 7 Days</b><div id="myStats"></div><div id="myList"></div></div></div>
<div id="quizDiv" style="display:none"><div class="card"><div id="qNum"></div><div style="font-size:22px;color:#ff5252;font-weight:bold" id="timerNum">45:00</div><div id="qText" style="font-size:19px;font-weight:600;margin:12px 0"></div><div id="opts"></div><button class="submit" id="submitBtn" onclick="submitAns()">SUBMIT</button><p id="feedback" style="text-align:center;font-weight:bold"></p><div style="display:flex;gap:8px"><button class="submit" onclick="prevQ()" style="background:#333;color:white">PREV</button><button class="submit" onclick="nextQ()" style="background:#00e5ff">NEXT</button></div><div class="palette" id="palette"></div><button class="submit" onclick="finishGame()" style="background:#d50000;color:white">FINISH</button></div></div>
<div id="resultDiv" style="display:none"><div class="merit"><h2 id="finalScore"></h2><p id="finalMsg"></p><p id="finalDetail"></p></div><div style="text-align:center"><button class="submit" onclick="downloadPDF()" style="max-width:580px;background:#00c853;color:white">📄 PDF DOWNLOAD</button><button class="submit" onclick="showHome()" style="max-width:580px">HOME</button></div><div class="card"><b>Review</b><div id="review"></div></div></div></div>
<script>
let isBn=false,user=null,questions=[],idx=0,answers=[],currentExam="",timeLeft=45*60,timerId=null,lastResult=null,examToken="",lastDetailed=[];
let LANG={en:{mainTitle:"🎓 VARSITY ADMISSION - SECURE",subTitle:"Secure Exam - Answers are checked on server, no one can hack",loginTitle:"📝 Login / Registration",lName:"Your Full Name",lEIIN:"College EIIN Number (6 Digits)",lClass:"Class",lRoll:"Class Roll",loginBtn:"✅ LOGIN & GET REG NO",loginHint:"EIIN is your college code. Wrong EIIN will not allow login. Example: Dhaka College = 108351",regTxt:"Reg No:",rollTxt:"Roll No:",bHome:"🏠 HOME",bRank:"🏆 RANKING",bMy:"📊 MY WEEK",chooseTxt:"Which University Exam Will You Take?",rankTitle:"🏆 Weekly Ranking - Everyone Can See",myTitle:"📊 My This Week - Last 7 Days",correct:"✅ CORRECT! +1",wrong:"❌ WRONG! -0.25 | Correct answer will be shown after exam."},bn:{mainTitle:"🎓 ভার্সিটি ভর্তি পরীক্ষা - নিরাপদ",subTitle:"নিরাপদ পরীক্ষা - উত্তর সার্ভারে চেক হবে, কেউ হ্যাক করতে পারবে না",loginTitle:"📝 লগইন / রেজিস্ট্রেশন",lName:"তোমার পুরো নাম",lEIIN:"কলেজের EIIN নম্বর (৬ সংখ্যা)",lClass:"ক্লাস",lRoll:"ক্লাস রোল",loginBtn:"✅ লগইন করো ও রেজি নম্বর নাও",loginHint:"EIIN হলো তোমার কলেজের কোড। ভুল EIIN দিলে লগইন হবে না। যেমন: ঢাকা কলেজ = ১০৮৩৫১",regTxt:"রেজি নম্বর:",rollTxt:"রোল নম্বর:",bHome:"🏠 হোম",bRank:"🏆 র‍্যাংকিং",bMy:"📊 আমার সপ্তাহ",chooseTxt:"কোন ভার্সিটির পরীক্ষা দিবা?",rankTitle:"🏆 সাপ্তাহিক র‍্যাংকিং - সবাই দেখতে পারবে",myTitle:"📊 আমার এই সপ্তাহ - গত ৭ দিন",correct:"✅ সঠিক! +১",wrong:"❌ ভুল! -০.২৫ | সঠিক উত্তর পরীক্ষা শেষে দেখানো হবে।"}};
function T(k){return isBn?LANG.bn[k]:LANG.en[k]}
function toBnNum(n){if(!isBn) return String(n); let m={'0':'০','1':'১','2':'২','3':'৩','4':'৪','5':'৫','6':'৬','7':'৭','8':'৮','9':'৯'}; return String(n).split('').map(c=>m[c]||c).join('')}
function setLang(b){isBn=b; applyLang()}
function applyLang(){document.getElementById('mainTitle').innerText=T('mainTitle');document.getElementById('subTitle').innerText=T('subTitle');document.getElementById('loginTitle').innerText=T('loginTitle');document.getElementById('lName').innerText=T('lName');document.getElementById('lEIIN').innerText=T('lEIIN');document.getElementById('lClass').innerText=T('lClass');document.getElementById('lRoll').innerText=T('lRoll');document.getElementById('loginBtn').innerText=T('loginBtn');document.getElementById('loginHint').innerText=T('loginHint');document.getElementById('regTxt').innerText=T('regTxt');document.getElementById('rollTxt').innerText=T('rollTxt');document.getElementById('bHome').innerText=T('bHome');document.getElementById('bRank').innerText=T('bRank');document.getElementById('bMy').innerText=T('bMy');document.getElementById('chooseTxt').innerText=T('chooseTxt');document.getElementById('rankTitle').innerText=T('rankTitle');document.getElementById('myTitle').innerText=T('myTitle');document.getElementById('btnBn').className='lang-btn '+(isBn?'active':'inactive');document.getElementById('btnEn').className='lang-btn '+(!isBn?'active':'inactive'); if(user) document.getElementById('welcomeTxt').innerText=(isBn?'স্বাগতম, ':'Welcome, ')+user.name+'!'; if(document.getElementById('quizDiv').style.display=='block') renderOpts(); renderExams();}
async function checkEIINLive(){let v=document.getElementById('eiinInput').value.trim(); if(v.length<6){document.getElementById('eiinMsg').innerText='';document.getElementById('collegeShow').style.display='none';return;} let r=await fetch('/api/check-eiin?eiin='+v); let j=await r.json(); document.getElementById('eiinMsg').innerText=j.msg; document.getElementById('eiinMsg').style.color=j.ok?'#00ff88':'#ff5252'; if(j.ok){document.getElementById('collegeShow').style.display='block'; document.getElementById('collegeShow').innerText='🏫 '+j.college;} else document.getElementById('collegeShow').style.display='none';}
async function doLogin(){let name=document.getElementById('nameInput').value.trim(); let eiin=document.getElementById('eiinInput').value.trim(); let cls=document.getElementById('classInput').value; let roll=document.getElementById('rollInput').value.trim(); if(!name||!eiin||!roll){alert(isBn?'সব ঘর পূরণ করো!':'Please fill all fields!'); return;} let r=await fetch('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,eiin,class_name:cls,roll})}); let j=await r.json(); if(!j.ok){alert(j.msg); return;} user=j.user; localStorage.setItem('adm_user_secure', JSON.stringify(user)); alert((isBn?'লগইন হয়ে গেছে!\\nরেজি নম্বর: ':'Login Done!\\nReg No: ')+user.reg_no+'\\nRoll: '+user.roll_no); showMain();}
function showMain(){document.getElementById('loginDiv').style.display='none'; document.getElementById('mainApp').style.display='block'; document.getElementById('showReg').innerText=user.reg_no; document.getElementById('showRoll').innerText=user.roll_no; document.getElementById('collegeTxt2').innerText=user.college+' | '+user.class_name+' | Roll: '+user.roll; document.getElementById('welcomeTxt').innerText=(isBn?'স্বাগতম, ':'Welcome, ')+user.name+'!'; showHome(); loadStats();}
async function loadStats(){let r=await fetch('/api/stats'); let j=await r.json(); document.getElementById('liveStats').innerText=(isBn?`মোট শিক্ষার্থী: ${toBnNum(j.total_users)} | মোট পরীক্ষা: ${toBnNum(j.total_exams)}`:`Total Students: ${j.total_users} | Total Exams: ${j.total_exams}`);}
let exams=[{name:"DU - A Unit",bn_name:"ঢাবি - এ ইউনিট",emoji:"🏛️",desc:"Physics | Chem | Math | Bio | Eng | Bangla",color:"#1a3a8a"},{name:"Medical",bn_name:"মেডিকেল",emoji:"🩺",desc:"Bio | Chem | Physics | Eng | GK",color:"#1a5c2a"},{name:"BUET",bn_name:"বুয়েট",emoji:"⚙️",desc:"Physics | Chem | Math",color:"#6a1a1a"},{name:"JU - D Unit",bn_name:"জাবি - ডি ইউনিট",emoji:"🧬",desc:"Bio | Chem | Physics | Bangla | Eng",color:"#6a1a6a"},{name:"CU - A Unit",bn_name:"চবি - এ ইউনিট",emoji:"🌊",desc:"Bio | Chem | Physics | Math | Bangla | Eng",color:"#8a4a1a"},{name:"Mixed Mock",bn_name:"মিক্সড মক",emoji:"🎲",desc:"Random 40 Q - Full Mock",color:"#333"}];
function renderExams(){let h=''; exams.forEach((e,i)=>{h+=`<div class="exam" style="background:${e.color}" onclick="startExam('${e.name}')">${e.emoji} ${isBn?e.bn_name:e.name}<small style="display:block;font-weight:normal;font-size:11px">${e.desc}</small></div>`}); document.getElementById('exams').innerHTML=h;}
function showHome(){document.getElementById('homeDiv').style.display='block';document.getElementById('rankDiv').style.display='none';document.getElementById('myDiv').style.display='none';document.getElementById('quizDiv').style.display='none';document.getElementById('resultDiv').style.display='none'; renderExams();}
function showRanking(){document.getElementById('homeDiv').style.display='none';document.getElementById('rankDiv').style.display='block';document.getElementById('myDiv').style.display='none';document.getElementById('quizDiv').style.display='none';document.getElementById('resultDiv').style.display='none'; loadRank('ALL');}
async function loadRank(exam){document.querySelectorAll('#rankTabs button').forEach(b=>b.classList.remove('active')); if(event) event.target.classList.add('active'); let r=await fetch('/api/leaderboard?exam='+exam); let j=await r.json(); if(j.length==0){document.getElementById('rankList').innerHTML='<p style="color:#aaa">'+(isBn?'এই সপ্তাহে এখনো কেউ পরীক্ষা দেয় নাই।':'No exam this week yet.')+'</p>'; return;} let h=''; j.forEach((x,i)=>{let cls=i==0?'rank1':''; let medal=i==0?'🥇':i==1?'🥈':i==2?'🥉':(i+1)+'.'; h+=`<div class="rank-item ${cls}"><span>${medal} ${x.name} - ${x.college} (${x.eiin})</span><span><b>${x.score} / 40</b> | ${x.exam_type}</span></div>`;}); document.getElementById('rankList').innerHTML=h;}
async function showMy(){document.getElementById('homeDiv').style.display='none';document.getElementById('rankDiv').style.display='none';document.getElementById('myDiv').style.display='block';document.getElementById('quizDiv').style.display='none';document.getElementById('resultDiv').style.display='none'; let r=await fetch('/api/my-history?reg='+user.reg_no); let j=await r.json(); let seven=j.filter(x=> new Date(x.created_at) > new Date(Date.now()-7*24*60*60*1000)); let wrong=seven.reduce((s,x)=>s+x.wrong,0); let correct=seven.reduce((s,x)=>s+x.correct,0); document.getElementById('myStats').innerHTML=(isBn?`গত ৭ দিনে পরীক্ষা: ${toBnNum(seven.length)}টি | সঠিক: ${toBnNum(correct)}টি | ভুল: ${toBnNum(wrong)}টি`:`Last 7 days Exams: ${seven.length} | Correct: ${correct} | Wrong: ${wrong}`); let h='<b>'+(isBn?'এই সপ্তাহের সব প্রশ্ন - উত্তরসহ:':'All Questions This Week - With Answers:')+'</b>'; seven.forEach(ex=>{h+=`<div style="background:#222;padding:10px;border-radius:10px;margin:8px 0"><b>${ex.exam_type} - ${ex.created_at} - Score ${ex.score}</b></div>`; let qs=JSON.parse(ex.questions||'[]'); qs.forEach((q,qi)=>{let qt=isBn?q.bn:q.q; let opts=isBn?q.bn_options:q.options; let your=q.selected>=0?opts[q.selected]:(isBn?'বাদ':'Skipped'); let corr=opts[q.correct]; h+=`<div style="font-size:13px;padding:6px;border-left:3px solid ${q.selected==q.correct?'#00ff88':'#ff5252'};margin:4px 0">${isBn?'প্রশ্ন':'Q'} ${qi+1}: ${qt}<br>${isBn?'তোমার উত্তর: ':'Your Answer: '}<span>${your}</span> | ${isBn?'সঠিক উত্তর: ':'Correct: '}<span style="color:#00ff88">${corr}</span></div>`;});}); document.getElementById('myList').innerHTML=h;}
async function startExam(examName){currentExam=examName; let r=await fetch('/api/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({exam_type:examName,reg_no:user.reg_no})}); let j=await r.json(); if(!j.ok){alert(j.msg); return;} examToken=j.token; questions=j.questions; answers=questions.map(()=>-1); idx=0; timeLeft=j.time; document.getElementById('homeDiv').style.display='none';document.getElementById('rankDiv').style.display='none';document.getElementById('myDiv').style.display='none';document.getElementById('resultDiv').style.display='none';document.getElementById('quizDiv').style.display='block'; showQ(); clearInterval(timerId); timerId=setInterval(()=>{timeLeft--; let m=Math.floor(timeLeft/60),s=timeLeft%60; document.getElementById('timerNum').innerText=(isBn?toBnNum(String(m).padStart(2,'0')+':'+String(s).padStart(2,'0')):String(m).padStart(2,'0')+':'+String(s).padStart(2,'0')); if(timeLeft<=0){clearInterval(timerId); finishGame();}},1000);}
function showQ(){let q=questions[idx]; document.getElementById('qNum').innerText=(isBn?`প্রশ্ন ${toBnNum(idx+1)} / ${toBnNum(questions.length)} - ${q.cat}`:`Question ${idx+1} / ${questions.length} - ${q.cat}`); document.getElementById('feedback').innerText=''; renderOpts(); renderPalette();}
function renderOpts(){let q=questions[idx]; document.getElementById('qText').innerText=isBn?q.bn:q.q; let opts=isBn?q.bn_o:q.o; let h=''; opts.forEach((o,i)=>{let cls='opt'; if(answers[idx]==i) cls+=' selected'; h+=`<div class="${cls}" onclick="selectOpt(${i})"><span>${String.fromCharCode(65+i)}. ${o}</span></div>`;}); document.getElementById('opts').innerHTML=h; document.getElementById('submitBtn').innerText=isBn?'✅ জমা দাও':'✅ SUBMIT';}
function selectOpt(i){answers[idx]=i; renderOpts();}
function submitAns(){ if(answers[idx]==-1){alert(isBn?'আগে একটা অপশন বেছে নাও!':'Please select an option first!'); return;} showQ(); if(idx<questions.length-1){idx++; showQ();} }
function renderPalette(){let h=''; answers.forEach((a,i)=>{let cls='pal'; if(a!=-1) cls+=' done'; if(i==idx) cls+=' current'; h+=`<div class="${cls}" onclick="goTo(${i})">${toBnNum(i+1)}</div>`}); document.getElementById('palette').innerHTML=h;}
function goTo(i){idx=i; showQ();} function nextQ(){if(idx<questions.length-1){idx++; showQ();}} function prevQ(){if(idx>0){idx--; showQ();}}
async function finishGame(){clearInterval(timerId); let r=await fetch('/api/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:examToken,answers:answers})}); let j=await r.json(); if(!j.ok){alert(j.msg); return;} lastResult=j; lastDetailed=j.detailed; document.getElementById('quizDiv').style.display='none'; document.getElementById('resultDiv').style.display='block'; document.getElementById('finalScore').innerText=(isBn?`${toBnNum(j.score)} / ${toBnNum(questions.length)}`:`${j.score} / ${questions.length}`); document.getElementById('finalMsg').innerText=j.score>=30?(isBn?'🏆 টপ মেধা! তুমি চান্স পাবা!':'🏆 TOP MERIT! You Will Get Chance!'):j.score>=20?(isBn?'🎉 চান্স পাওয়ার সম্ভাবনা অনেক বেশি!':'🎉 High Possibility To Get Chance!'):(isBn?'📚 আরো পড়তে হবে!':'📚 Need More Study!'); document.getElementById('finalDetail').innerText=(isBn?`সঠিক: ${toBnNum(j.correct)} | ভুল: ${toBnNum(j.wrong)} | বাদ: ${toBnNum(j.skipped)}`:`Correct: ${j.correct} | Wrong: ${j.wrong} | Skipped: ${j.skipped}`); let rev=''; j.detailed.forEach((q,i)=>{if(q.selected!=q.correct){let qt=isBn?q.bn:q.q; let your=q.selected>=0?(isBn?q.bn_options[q.selected]:q.options[q.selected]):(isBn?'বাদ':'Skipped'); let corr=isBn?q.bn_options[q.correct]:q.options[q.correct]; rev+=`<p style="font-size:13px">${isBn?'প্রশ্ন':'Question'} ${i+1}: ${qt}<br>${isBn?'তোমার উত্তর: ':'Your Answer: '}<span style="color:#ff5252">${your}</span> | ${isBn?'সঠিক উত্তর: ':'Correct: '}<span style="color:#00ff88">${corr}</span></p>`}}); document.getElementById('review').innerHTML=rev||(isBn?'সব ঠিক!':'All Correct!');}
function downloadPDF(){if(!lastResult) return; let w=window.open('','_blank'); let html=`<html><head><title>Result</title><style>body{font-family:sans-serif;padding:20px} .q{border:1px solid #ccc;padding:10px;border-radius:10px;margin:8px 0}</style></head><body><h1>${isBn?'ভার্সিটি ভর্তি পরীক্ষা - ফলাফল পত্র':'Varsity Admission - Result Paper'}</h1><p>${isBn?'নাম: ':'Name: '}${user.name} | ${isBn?'রেজি: ':'Reg: '}${user.reg_no} | ${isBn?'রোল: ':'Roll: '}${user.roll_no} | ${isBn?'কলেজ: ':'College: '}${user.college} (${user.eiin}) | ${isBn?'পরীক্ষা: ':'Exam: '}${currentExam} | ${isBn?'নম্বর: ':'Score: '}${lastResult.score}</p><button onclick="window.print()">Print / Save PDF</button>`; lastDetailed.forEach((q,i)=>{let qt=isBn?q.bn:q.q; let opts=isBn?q.bn_options:q.options; let your=q.selected>=0?opts[q.selected]:(isBn?'বাদ':'Skipped'); let corr=opts[q.correct]; html+=`<div class="q"><b>Q${i+1}</b> ${qt}<br>${opts.map((o,oi)=>`${String.fromCharCode(65+oi)}. ${o}${oi==q.correct?' ✅':''}`).join('<br>')}<br><b>${isBn?'তোমার উত্তর: ':'Your Answer: '}</b>${your} | <b>${isBn?'সঠিক উত্তর: ':'Correct: '}</b>${corr}</div>`}); html+='</body></html>'; w.document.write(html); w.document.close(); setTimeout(()=>w.print(),500);}
let saved=localStorage.getItem('adm_user_secure'); if(saved){user=JSON.parse(saved); showMain();} else {setLang(false);}
</script></body></html>
"""

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
