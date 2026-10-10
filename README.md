# ScamShield

**Paste a suspicious message, link, or call recording. Find out in seconds if it's a scam, and why.**

ScamShield is a free tool that helps ordinary people spot online fraud: fake bank messages, UPI "collect request" tricks, prize scams, phishing links and scam phone calls. It gives a simple answer (**Safe**, **Suspicious**, or **Scam**) and explains the warning signs in plain language.

---

## Why we built this

Online fraud is rising in India. Scammers send messages like:

> "Dear customer, your KYC has expired. Update now or your account will be blocked in 24 hours."

These messages look official and create panic. Most people have no quick way to check whether a message is real, so they click, share an OTP, or send money.

ScamShield is the quick check. Before you tap a link or reply, paste it here first.

---

## What it does

| Feature | What it means for you |
|---|---|
| **Message check** | Paste an SMS or WhatsApp message and get a verdict with reasons |
| **Link check** | Spots fake websites that imitate banks or brands (for example `sbi-kyc-update.xyz`) |
| **Call recording check** | Upload a recording of a suspicious call and ScamShield checks what was said *(planned)* |
| **Community reports** | Report a scam number, UPI ID or link so others are warned *(planned)* |
| **Clear explanations** | Instead of a mystery score, you see reasons such as "Pushes a 24-hour deadline" |
| **Privacy first** | Your messages are checked and not saved |

---

## What a result looks like

You paste:

> Dear customer, your SBI KYC has expired. Update now at http://sbi-kyc-update.xyz or your account will be blocked in 24 hrs.

ScamShield shows:

- **Verdict:** Scam (93% risk)
- **Why we flagged it:**
  - Says your KYC has expired
  - Pushes a 24-hour deadline
  - Link imitates SBI but is not an official website
- **What to do:** Don't click the link. If you already paid or shared an OTP, call **1930** and contact your bank.

---

## How it works (in simple words)

ScamShield uses three checks and combines them, a bit like asking three experts and going with the overall opinion.

1. **Rules check:** looks for classic scam tricks such as asking for your OTP, creating panic, pretending to be a bank, or promising prizes.
2. **Learning model:** a machine learning model trained on examples of scam and genuine messages.
3. **Link check:** looks at web addresses for warning signs such as fake lookalike names, unusual endings, or link shorteners.

If a phone number, UPI ID or link has been reported by the community before, that raises the risk score. The final score becomes the verdict.

```
Your message / link / call
          |
   Clean up (calls are turned into text first)
          |
   +------+-------------+
   |      |             |
 Rules   Learning     Link
 check   model        check
   |      |             |
   +------+------+------+
                 |
   Combine scores + community reports
                 |
      Verdict: Safe / Suspicious / Scam
         with clear reasons
```

---

## Who is this for?

- Anyone who receives suspicious SMS, WhatsApp messages or calls
- Students and families, especially people less familiar with online fraud
- Hackathon judges and developers who want to see an explainable fraud detector

---

## What ScamShield cannot do

We want to be honest about the limits:

- **It is not perfect.** It can miss a clever scam or occasionally flag a genuine message. Treat the result as strong guidance, not a guarantee.
- **It cannot find where a scammer is.** A transaction ID, UPI ID or payment link does not contain location information, and ScamShield does not try to trace anyone.
- **It cannot recover lost money.** If you have been scammed, act quickly (see the next section).
- **It does not replace your bank.** When in doubt, contact your bank using the number on your card or the official website.

---

## If you have been scammed

Act fast. The first hour matters most.

1. Call the National Cyber Crime Helpline: **1930**
2. File a complaint at **cybercrime.gov.in**
3. Contact your bank right away and ask them to block the transaction or freeze the card
4. Change passwords and PINs for any account you may have exposed

---

## Tech stack

| Part | Tool |
|---|---|
| Backend | Python, FastAPI |
| Learning model | scikit-learn |
| Speech to text | Whisper |
| Database | SQLite |
| Website | HTML, CSS, JavaScript |

---

## Project structure

```
scamshield/
├── app/                  # backend (API and detection logic)
│   ├── api/              # web endpoints
│   ├── core/             # rules, model, link checker, scoring
│   ├── db/               # database models
│   ├── schemas/          # request and response formats
│   └── data/             # scam patterns, brand list, trained model
├── training/             # scripts to train the model
├── frontend/             # the website people use
├── tests/                # automated tests and sample messages
├── requirements.txt
└── README.md
```

---

## Getting started

You need **Python 3.11 or newer** and **Git**.

```bash
# 1. Get the code
git clone https://github.com/subrata131/scamshield.git
cd scamshield

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate        # on Windows: venv\Scripts\activate

# 3. Install requirements
pip install -r requirements.txt

# 4. Train the model (one time)
python training/train.py

# 5. Start the app
uvicorn app.main:app --reload
```

Then open **http://127.0.0.1:8000** in your browser. Interactive API docs are at **http://127.0.0.1:8000/docs**.

### Run the tests

```bash
pytest
```

---

## API overview

| Method | Path | What it does |
|---|---|---|
| POST | `/api/analyze/text` | Check a message |
| POST | `/api/analyze/url` | Check a link |
| POST | `/api/analyze/audio` | Check a call recording |
| POST | `/api/report` | Report a number, UPI ID or link |
| GET | `/api/reputation` | See how often something was reported |
| POST | `/api/feedback` | Tell us if a verdict was right or wrong |

Example:

```bash
curl -X POST http://127.0.0.1:8000/api/analyze/text \
  -H "Content-Type: application/json" \
  -d '{"text": "Your KYC has expired. Click here to update or your account will be blocked."}'
```

---

## Privacy

- Messages are analyzed in memory and **not stored**.
- We keep only a one-way fingerprint (hash) of each check to measure accuracy. The original text cannot be recovered from it.
- Uploaded call recordings are deleted right after they are turned into text.
- The app never opens or visits the links you paste. It only examines the text of the address.
- Community reports are optional and should not include personal details.

---

## Project status

- [x] Idea, design and plan
- [ ] Message checker (rules + learning model)
- [ ] Link checker
- [ ] Website with verdict screen
- [ ] Community reports
- [ ] Call recording check
- [ ] Hindi and Bengali support

*Update this list as features are completed.*

---

## Roadmap

- Browser extension that warns you before you open a risky link
- WhatsApp and Telegram bot
- Support for more Indian languages
- Fake scholarship and fake job scam detection

---

## Contributing

Ideas and improvements are welcome.

1. Fork the repository
2. Create a branch: `git checkout -b my-improvement`
3. Make your changes and add tests
4. Open a pull request describing what you changed

You can also help by sharing **real scam message examples** (with names, numbers and personal details removed) to make detection better.

---

## Disclaimer

ScamShield is an educational and awareness tool. Its results are automated estimates and are not legal, financial or professional advice. Always verify with your bank or the official organization before acting on any message.

---

## Author

Built by **Subrata Das** ([@subrata131](https://github.com/subrata131)).

## License

Add a license of your choice (for example MIT) before publishing.
