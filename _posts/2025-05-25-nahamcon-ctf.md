---
title: "NahamCon CTF 2025"
date: 2025-05-25 00:00 +0800
categories: [CTF]
tags: [CTF, Web, Forensics, JWT, API, Fuzzing, ROT Cipher, Zip Recovery, 7zip, Strings, Burp Suite, Intruder, WebSocket, Token Forgery, Console Exploit]
# image: https://github.com/user-attachments/assets/a7dcf9de-a7c7-4230-bb72-4119c8f02448
---

During this ctf I solved mainly in Web and some warmups involving some forensics. 

## Warmup

### Quartet

![image](https://github.com/user-attachments/assets/c6a7cf13-1ef9-40cb-8b4b-4939f7d5257e)

We're given four files name [quartet.z01](https://github.com/kryzii/WRITEUPS/blob/main/2025/NAHAMCON%202025/WARMUP/QUARTET/quartet.z01), [quartet.z02](https://github.com/kryzii/WRITEUPS/blob/main/2025/NAHAMCON%202025/WARMUP/QUARTET/quartet.z02),  [quartet.z03](https://github.com/kryzii/WRITEUPS/blob/main/2025/NAHAMCON%202025/WARMUP/QUARTET/quartet.z03), [quartet.z04](https://github.com/kryzii/WRITEUPS/blob/main/2025/NAHAMCON%202025/WARMUP/QUARTET/quartet.z04) and we are required to retrieve the contents to find the flag

.z01 - .z04 are chunks of splits archieve. Normally we also get quartet.zip, but in this case .zo1 is the first segment.

So to retrieve the content, we can use 7z and here's how to do it in kali
```
7z x quartet.z01
```
After that, we will be getting quartet.jpeg 

![quartet](https://github.com/user-attachments/assets/da981370-1b09-4623-a993-5963d7faf129)

Grep "flag" from the strings we will get the flag
```
strings quartet.jpeg | grep flag
```
![image](https://github.com/user-attachments/assets/b776a09e-2c88-4646-be87-5afadeb46757)

```
flag{8f667b09d0e821f4e14d59a8037eb376}
```

### Screenshot

![image](https://github.com/user-attachments/assets/7b391517-d016-4ee6-b989-231d68127548)


In this Challenge, we are provided with raw data screnshot of unknown files. 

To solve this, we need to recover the files.

![Screenshot](https://github.com/user-attachments/assets/4e74db2c-25e3-4576-bcbb-406795d8889a)


Here's the hex values to be copy: 
```
504b03043300010063002f02b55a00000000430000002700000008000b00666c61672e74787401990700020041450300003d42ffd1b35f95031424f68b65c3f57669f14e8df0003fe240b3ac3364859e4c2dbc3c36f2d4acc403761385afe4e3f90fbd29d91b614ba2c6efde11b71bcc907a72ed504b01023f033300010063002f02b55a00000000430000002700000008002f000000000000002080b48100000000666c61672e7478740a00200000000000010018008213854307cadb01000000000000000000000000000000000199070002004145030000504b0506000000000100010065000000740000000000
```
After that, save it as flag.hex

We already know that it suppose to be zip file so we shall then rebuild the file from hex to zip
```
xxd -r -p flag.hex flag.zip
```

the password is there from the challenge description
```
unzip -P password flag.zip
```
![image](https://github.com/user-attachments/assets/c5e7add6-e581-4e21-878c-caedd1efcff6)

```
flag{907e5bb257cd5fc818e88a13622f3d46}
```

## Web

### Fuzzies

![image](https://github.com/user-attachments/assets/ec19a64a-e750-45f8-8ffc-f9afb2332d5c)

This challenge involved finding five hidden flags through a series of web-based exploits. Including endpoint fuzzing, login brute-forcing, and API enumeration. I managed to retrieve four out of five flags, uncovering most of the application’s logic and data exposure paths.


![image](https://github.com/user-attachments/assets/b5e846fb-8dce-4d86-80ae-516b2749140b)

![image](https://github.com/user-attachments/assets/e3ca0624-3c5a-47cc-a643-e47b83a65721)

![image](https://github.com/user-attachments/assets/ee28034f-d135-4a97-9604-1d9b94e1e6ce)

![image](https://github.com/user-attachments/assets/459a2207-5f2a-48ca-9760-6fd9eda698e3)

#### Flag #1

by using the wordlist and FUZZing by using intruder, i find this endpoint: 

``
/api/users
``
but, when trying to access ``/{id}`` it gave that an error:

![image](https://github.com/user-attachments/assets/309c439c-f2c4-488a-aaac-ac1b78b97e58)

How to bypass? by adding ``/{id}/log`` 

![image](https://github.com/user-attachments/assets/27e3b7cc-b599-4be1-a333-01dbcf989f18)


After that, we can simply bruteforce to find the right id for it from ``1 - 100``


```
/api/users/0/log
/api/users/1/log
...
/api/users/100/log
```

![image](https://github.com/user-attachments/assets/520f5d6b-3214-426f-8575-633ac9d50de8)


``flag{31ef61815ae2b7209d0493b996608be5}``

#### Flag #2

Log in as admin. From first flag we will get the admin details ``"username":"brian.1954"``
Then bruteforce the password with wordlist ``password.txt`` given

![image](https://github.com/user-attachments/assets/ef0a15f6-5ec5-41eb-99e5-c1384a902f17)

```
username : brian.1954
password : dallas
```

After that, simply log in with the given username and password. The flag will be in the admin dashboard

![image](https://github.com/user-attachments/assets/1ff71d2b-aa29-4ef6-be8b-d840af0e8fba)

``flag{8a8b9661b3bd2baa2c74347a6c5cc0fc}``

#### Flag #3

For this flag, in the ``/admin/messages/`` each message has it own ``{id}``
So, again we use intruder to bruteforce this

```
/admin/messages/0
/admin/messages/1
...
/admin/messages/1000
```

We are seeing an extra message id which then provide us with the third flag:

![image](https://github.com/user-attachments/assets/a7249edc-17bf-4f80-bd28-eeae505596f5)
![image](https://github.com/user-attachments/assets/343cc492-0957-4f4e-aafe-5ddfeeefe87c)

``flag{3a5aed9baa7c7b3ba6cbe4a15425af3f}``

#### Flag #4

From Flag #3 question we are given with ``666e8400-e29b-41d4-a716-446655440666``

![image](https://github.com/user-attachments/assets/3877cf65-4440-4906-8fee-4293567bdec3)

How to use this? Upon reviewing api-endpoints for each request. I find that in `/collection`

![Screenshot 2025-05-26 022134 copy](https://github.com/user-attachments/assets/b5b93eab-b713-44ec-a576-57f22bfb4f05)

We had json files that are storing the data of the fuzzies bear with GET request on api-endpoint called ``/api/fuzzies``

```json
[
    {
        "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "name": "Original Fuzzy",
        "image": "\/images\/fuzzies\/original.png",
        "description": "The one that started it all! This classic bear features the signature soft, fuzzy fur that made Fuzzies famous. Perfect for cuddling and bedtime stories.",
        "hidden": false
    },
    {
        "id": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
        "name": "Cool Fuzzy",
        "image": "\/images\/fuzzies\/cool.png",
        "description": "The hippest bear in town! With its stylish sunglasses and laid-back attitude, this Fuzzy was every kid's best friend for summer adventures.",
        "hidden": false
    },
    {
        "id": "c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f",
        "name": "Punk Fuzzy",
        "image": "\/images\/fuzzies\/punk.png",
        "description": "Rock out with this rebellious bear! With its spiky fur and edgy style, this Fuzzy was perfect for kids who wanted to stand out from the crowd.",
        "hidden": false
    },
    {
        "id": "d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f8g",
        "name": "Roller Fuzzy",
        "image": "\/images\/fuzzies\/roller.png",
        "description": "Skate into fun with this sporty bear! Designed for active kids who loved roller skating and outdoor adventures.",
        "hidden": false
    },
    {
        "id": "e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8g9h",
        "name": "Sporty Fuzzy",
        "image": "\/images\/fuzzies\/sporty.png",
        "description": "The athletic bear that cheered on every game! Perfect for young sports enthusiasts who wanted a fuzzy mascot for their team.",
        "hidden": false
    },
    {
        "id": "f6a7b8c9-d0e1-4f2a-3b4c-5d6e7f8g9h0i",
        "name": "Tie-Dye Fuzzy",
        "image": "\/images\/fuzzies\/tie-dye.png",
        "description": "Peace, love, and fuzzy hugs! This colorful bear brought the psychedelic 80s style to the world of plush toys.",
        "hidden": false
    },
    {
        "id": "g7h8i9j0-k1l2-4m3n-4o5p-6q7r8s9t0u1v",
        "name": "Zebra Fuzzy",
        "image": "\/images\/fuzzies\/zebra.png",
        "description": "A wild twist on the classic Fuzzy! With its unique striped pattern, this bear was perfect for kids who loved animals and adventure.",
        "hidden": false
    }
]
```

![image](https://github.com/user-attachments/assets/28ad0a2a-b95f-4c81-b92f-4306a65c7c08)

That's mean UUID we had before should be the id for fuzzies: 

``http://challenge.nahamcon.com:31526/api/fuzzies?id=666e8400-e29b-41d4-a716-446655440666``

![image](https://github.com/user-attachments/assets/d5698c92-0c9f-4374-a609-714d2adf27a4)

``flag{e5f170b92990f73980b48af57f442e1f}``

### Infinite Queue

![Screenshot 2025-05-25 161440](https://github.com/user-attachments/assets/addde689-ac3c-4373-9a90-69ba06f118f1)

![Screenshot 2025-05-25 161937](https://github.com/user-attachments/assets/db94717d-a685-4059-a63f-e7fa44888fae) ![Screenshot 2025-05-25 162142](https://github.com/user-attachments/assets/4acffa24-0052-42eb-8fcb-b8c00a667396)

For the exploitation part, we are required to intercept by using Burpsuite. 

After the POST **/join_queue** request, we will be response with the token that represent for our queue time. 

![image](https://github.com/user-attachments/assets/5f8f4f1b-3120-4b0e-837f-3bdd6ee5fdf9)

First, we suppose to change the token (by using https://jwt.io/) to cut the queue time for buying the tickets from:

![Screenshot 2025-05-25 163128](https://github.com/user-attachments/assets/99c1409f-e491-4657-a3ed-125907440608)

to:

![Screenshot 2025-05-25 163142](https://github.com/user-attachments/assets/188c69a9-26ff-4138-b24d-cb6539129157)

Next, intercept the POST request to **/check_queue**, and change with our new token. 

After intercepting the **/check_queue** the response will give us an error that saying the *JWT_SECRET* for our jwt token is incorrect. 

![image](https://github.com/user-attachments/assets/e82c2358-9657-496e-bc75-6f1814b49202)

But, in the error it is actually included the correct *JWT_SECRET* which something that are not suppose to be expose:

```
"JWT_SECRET":"4A4Dmv4ciR477HsGXI19GgmYHp2so637XhMC"
```

So we can use the *JWT_SECRET* given and change our token with valid jwt secret and reintercept the request again with the working jwt token. 

Next, be sure to always change to our jwt token to each request such as **/purchase** and **/purchase?html=true**

![image](https://github.com/user-attachments/assets/5c51e150-8b5e-4493-abf5-ee9567b952c4)

![image](https://github.com/user-attachments/assets/e61c5c17-96a6-4023-a94e-ac0857c3c0f3)

By then, we will be provided with pdf file with confirmation code as the flag/we can simply get those from the **/purchase?html=true** response

![Screenshot 2025-05-25 164145](https://github.com/user-attachments/assets/ff2e5718-8e87-47eb-8835-e8575c28dfd2)
![image](https://github.com/user-attachments/assets/b44c541e-17a4-48d5-8b13-61d9c182e664)

```
flag{b1bd4795215a7b81699487cc7e32d936}
```

### My First CTF 

![image](https://github.com/user-attachments/assets/0290340b-e751-4c51-ad5c-eaab6bf1b52f)

For, this challenge. The webapp had nothing much going on, only simple index.html, and those bg.png and rotten.jpg file

![image](https://github.com/user-attachments/assets/f828b3c2-b2e3-4d0a-b8b9-2e6e60625ffb)

So, my first guess was directly try and guess a few common hidden endpoint for a ctf challenge until i find there's flag.txt

![image](https://github.com/user-attachments/assets/981a8992-bd97-48be-9485-461f3c7ee9f1)

This is where i realise that i misslook they has given me a hint: 
**On second thoughts I should have probably called this challenge "Nz Gjstu DUG"** 
which Nz Gjstu DUG = My First CTF decrypted in rot1. I figured it could be something related with rot encrypted and with the flag.txt

![image](https://github.com/user-attachments/assets/25cff5b4-d1a2-445a-8480-7694b7edf87b)

So i dedcided to encrypt the flag.txt in rot1 too and use it as the webapp endpoint. 

![image](https://github.com/user-attachments/assets/5874fb35-079b-4661-b0c2-ec1b41efb922)

![image](https://github.com/user-attachments/assets/71f701cd-5ae2-4127-a567-31e1c4cbca65)

Bingo! after that we will be given with a file containing the flag. Simply preview the content and get the flag:

![image](https://github.com/user-attachments/assets/2dc5d4ff-976b-47d9-bc88-393aa320113c)

```
flag{b67779a5cfca7f1dd120a075a633afe9}
```

### My Second CTF

![image](https://github.com/user-attachments/assets/1a29d56d-1b3c-45eb-b71a-5942f6511ac1)

For this challenge, its the second version from [My First CTF](https://github.com/Kr3yzi/CTF-WRITEUPS/tree/main/2025/NAHAMCON%202025/WEB/MY%20FIRST%20CTF#readme).
The only difference is we are given wordlist.txt. Same as before, but without the flag.txt endpoint.

![image](https://github.com/user-attachments/assets/2a7b8d18-0f0f-49be-9960-ea990927c14b)

Soooo my guess, its Burp Intruder time! Oh before we forget, last time. It's encrypted in ROT1. But this, i cant risk my time to guess which ROT.  
I ask cursor to provide me with a script that:
- Encrypt the wordlist.txt content to all ROT
- Generated updated wordlist with all possible ROT encrypted
  
After that, by using Burpsuite. We simply send the GET request to burp intruder

![image](https://github.com/user-attachments/assets/36ba7e1c-dab3-43f8-ad8b-43b65435c5f5)

Add position for our payload

![image](https://github.com/user-attachments/assets/24d8e0a8-9f30-45d9-8193-69416ca54d52)

Use our ROT encrypted wordlist for it.

![image](https://github.com/user-attachments/assets/5f3475ab-dc54-4811-b050-2aaf31269235)

We will then get a single request where the status code is different from others

![image](https://github.com/user-attachments/assets/b45b616c-a629-4e79-9876-8be987d8c78e)

Upon visiting the endpoint, we will be redirected and getting error that says:

![image](https://github.com/user-attachments/assets/52f42408-3aec-41ad-ade8-958843ac2592)

We then need to bruteforce one more time with our current wordlist. 

But this time, its for our parameter. So, the position for the payload:
```
GET /fgdwi/?§a§=meow
```
![image](https://github.com/user-attachments/assets/c554f960-96e2-466d-8852-6e672260dcf3)

Why, does the payload needed to have **?§a§=meow** it's because the error says that missing parameter and not value. 
So the value could be anything else other than "*meow*" it could be "*dog*" or even "*cat*". Also, fgdwi = debug, which is encrypted by ROT2.

For better understanding, After finding the right parameter. And the response that we get is an error, for the value such as missing or incorrect. 
That's only when we need to have a correct value for it instead. 

After we are done with the intruder, we can find only one request that has a different length from others. Reviewing the response we will get the flag:   

![image](https://github.com/user-attachments/assets/f05b1f88-7ef2-44ed-a2f4-8982106b64e0)

```
flag{9078bae810c524673a331aeb58fb0ebc}
```

### My Third CTF

![image](https://github.com/user-attachments/assets/fe08129e-5474-4a0f-ba58-18774cc9033a)

For this challenge, its the third version from [My First CTF](https://github.com/Kr3yzi/CTF-WRITEUPS/tree/main/2025/NAHAMCON%202025/WEB/MY%20FIRST%20CTF#readme) and [My Second CTF](https://github.com/Kr3yzi/CTF-WRITEUPS/tree/main/2025/NAHAMCON%202025/WEB/MY%20SECOND%20CTF#readme).
The only difference is we are given wordlist.txt same as the second one.

![image](https://github.com/user-attachments/assets/6e5eb0e1-d111-48c3-9e29-5fb570ce383e)

From the wordlist given,
I ask cursor to provide me with a script that:
- Encrypt the wordlist.txt content to all ROT
- Generated updated wordlist with all possible ROT encrypted

After that, by using Burpsuite. We simply send the GET request to burp intruder and add position for our payload

![image](https://github.com/user-attachments/assets/523dd72e-051e-4f39-bb2e-d9bff18ce541)

Using our ROT encrypted wordlist for it. We will then get a single request where the status code is different from others

![image](https://github.com/user-attachments/assets/65505e12-5915-4be4-9688-106b59b81e3e)

Upon visiting the endpoint, we will be redirected and getting error that says 403 Forbidden:

![image](https://github.com/user-attachments/assets/2893dd2e-c1ba-44a6-ba65-22c04ce1b2fa)

To bypass, simply bruteforce each of the directories multiple times with our wordlist payload till we got our final url. 
Here's the payload position for our intruder

![image](https://github.com/user-attachments/assets/5cf2968c-5926-4872-8b6f-1b3a9972856d) 
![image](https://github.com/user-attachments/assets/d8913b91-c459-43b7-b55b-657c23bb211d) ![image](https://github.com/user-attachments/assets/9364655c-f452-4784-a88c-1c12e24d256d)

http://challenge.nahamcon.com:30653/qbhf/oguucig/wrnhq/lewl/

![image](https://github.com/user-attachments/assets/11d42284-be7a-4ef5-932d-c745e2488e4e)
![image](https://github.com/user-attachments/assets/8f98b501-cf41-4c2b-8299-a1933e76641c)

```
flag{afd87cae63c08a57db7770b4e52081d3}
```

### SNAD

![image](https://github.com/user-attachments/assets/2c38403b-4479-4bba-9f60-b86176d03f6e)

We need to pinpoint 7 exact colors at the required X and Y

![image](https://github.com/user-attachments/assets/52f7cffd-9344-4e0a-a738-ac3bb699bc9b)

From this, js/script.js we have the exact colorHue for each and exact pinpoint

```js 
const requiredGrains = 7
  , targetPositions = [{
    x: 367,
    y: 238,
    colorHue: 0
}, {
    x: 412,
    y: 293,
    colorHue: 40
}, {
    x: 291,
    y: 314,
    colorHue: 60
}, {
    x: 392,
    y: 362,
    colorHue: 120
}, {
    x: 454,
    y: 319,
    colorHue: 240
}, {
    x: 349,
    y: 252,
    colorHue: 280
}, {
    x: 433,
    y: 301,
    colorHue: 320
}]
  , tolerance = 15
  , hueTolerance = 20;
let particles = []
  , grid = []
  , isMousePressed = !1
  , colorIndex = 0
  , flagRevealed = !1
  , targetIndicatorsVisible = !1
  , gravityStopped = !1;
function getRainbowColor() {
    return color("hsb(" + (colorIndex = (colorIndex + 5) % 360) + ", 100%, 90%)")
}
function getSpecificColor(e) {
    return color("hsb(" + e + ", 100%, 90%)")
}
async function retrieveFlag() {
    let e = document.getElementById("flag-container");
    e.style.display = "block";
    try {
        let t = particles.filter(e => e.settled).map(e => ({
            x: Math.floor(e.x),
            y: Math.floor(e.y),
            colorHue: e.colorHue
        }))
          , o = await fetch("/api/verify-ctf-solution", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                particleData: t
            })
        })
          , i = await o.json()
          , r = e.querySelector(".loading");
        r && r.remove(),
        i.success ? (e.querySelector("p").textContent = "SNAD!",
        document.getElementById("flag-text").textContent = i.flag) : (e.querySelector("p").textContent = i.message,
        document.getElementById("flag-text").textContent = "",
        setTimeout( () => {
            e.style.display = "none",
            flagRevealed = !1
        }
        , 3e3))
    } catch (l) {
        console.error("Error retrieving flag:", l),
        document.getElementById("flag-text").textContent = "Error retrieving flag. Please try again.";
        let s = e.querySelector(".loading");
        s && s.remove()
    }
}
function injectSand(e, t, o) {
    if (isNaN(e) || isNaN(t) || isNaN(o))
        return console.error("Invalid parameters. Usage: injectSand(x, y, hue)"),
        !1;
    o = (o % 360 + 360) % 360;
    let i = new Particle(e,t,{
        colorHue: o,
        settled: !0,
        skipKeyCheck: !0,
        vx: 0,
        vy: 0
    });
    particles.push(i);
    let r = floor(e)
      , l = floor(t);
    return r >= 0 && r < width && l >= 0 && l < height && (grid[l][r] = !0),
    i
}
function toggleGravity() {
    gravityStopped = !gravityStopped,
    console.log(`Gravity ${gravityStopped ? "stopped" : "resumed"}`)
}
class Particle {
    constructor(e, t, o={}) {
        this.x = void 0 !== o.x ? o.x : e,
        this.y = void 0 !== o.y ? o.y : t,
        this.size = o.size || random(2, 4),
        void 0 !== o.colorHue ? (this.colorHue = o.colorHue,
        this.color = getSpecificColor(o.colorHue)) : (this.color = getRainbowColor(),
        this.colorHue = colorIndex),
        this.vx = void 0 !== o.vx ? o.vx : random(-.5, .5),
        this.vy = void 0 !== o.vy ? o.vy : random(0, 1),
        this.gravity = o.gravity || .2,
        this.friction = o.friction || .98,
        this.settled = o.settled || !1,
        o.skipKeyCheck || this.checkSpecialGrain()
    }
    checkSpecialGrain() {
        keyIsDown(82) ? (this.color = getSpecificColor(0),
        this.colorHue = 0) : keyIsDown(79) ? (this.color = getSpecificColor(40),
        this.colorHue = 40) : keyIsDown(89) ? (this.color = getSpecificColor(60),
        this.colorHue = 60) : keyIsDown(71) ? (this.color = getSpecificColor(120),
        this.colorHue = 120) : keyIsDown(66) ? (this.color = getSpecificColor(240),
        this.colorHue = 240) : keyIsDown(73) ? (this.color = getSpecificColor(280),
        this.colorHue = 280) : keyIsDown(86) && (this.color = getSpecificColor(320),
        this.colorHue = 320)
    }
    update(e) {
        if (this.settled || gravityStopped)
            return;
        this.vy += this.gravity,
        this.vx *= this.friction;
        let t = this.x + this.vx
          , o = this.y + this.vy;
        (t < 0 || t >= width || o >= height) && (o >= height && (o = height - 1,
        this.settled = !0),
        t < 0 && (t = 0),
        t >= width && (t = width - 1));
        let i = min(floor(o) + 1, height - 1)
          , r = floor(t);
        if (i < height && !e[i][r])
            this.x = t,
            this.y = o;
        else {
            let l = max(r - 1, 0)
              , s = min(r + 1, width - 1);
            i < height && !e[i][l] ? (this.x = t - 1,
            this.y = o,
            this.vx -= .1) : i < height && !e[i][s] ? (this.x = t + 1,
            this.y = o,
            this.vx += .1) : (this.x = r,
            this.y = floor(this.y),
            this.settled = !0)
        }
        let c = floor(this.x)
          , a = floor(this.y);
        c >= 0 && c < width && a >= 0 && a < height && (e[a][c] = !0)
    }
    draw() {
        noStroke(),
        fill(this.color),
        circle(this.x, this.y, this.size)
    }
}
function setup() {
    createCanvas(windowWidth, windowHeight),
    resetGrid(),
    document.addEventListener("keydown", function(e) {
        "t" === e.key && (targetIndicatorsVisible = !targetIndicatorsVisible),
        "x" === e.key && toggleGravity()
    }),
    window.injectSand = injectSand,
    window.toggleGravity = toggleGravity,
    window.particles = particles,
    window.targetPositions = targetPositions,
    window.checkFlag = checkFlag
}
function resetGrid() {
    grid = [];
    for (let e = 0; e < height; e++) {
        grid[e] = [];
        for (let t = 0; t < width; t++)
            grid[e][t] = !1
    }
    flagRevealed = !1;
    let o = document.getElementById("flag-container");
    o.style.display = "none"
}
function draw() {
    if (background(30),
    isMousePressed && mouseX > 0 && mouseX < width && mouseY > 0 && mouseY < height)
        for (let e = 0; e < 3; e++) {
            let t = new Particle(mouseX + random(-5, 5),mouseY + random(-5, 5));
            particles.push(t)
        }
    if (targetIndicatorsVisible)
        for (let o of (stroke(255, 150),
        strokeWeight(1),
        targetPositions))
            noFill(),
            stroke(o.colorHue, 100, 100),
            circle(o.x, o.y, 30);
    let i = [];
    for (let r = 0; r < height; r++) {
        i[r] = [];
        for (let l = 0; l < width; l++)
            i[r][l] = !1
    }
    for (let s of particles) {
        s.update(grid),
        s.draw();
        let c = floor(s.x)
          , a = floor(s.y);
        c >= 0 && c < width && a >= 0 && a < height && (i[a][c] = !0)
    }
    grid = i,
    checkFlag(),
    fill(255),
    textSize(16),
    text("Particles: " + particles.length, 10, height - 20)
}
function checkFlag() {
    if (flagRevealed)
        return;
    let e = 0
      , t = [];
    for (let o of targetPositions) {
        let i = !1;
        for (let r of particles)
            if (r.settled) {
                let l = dist(r.x, r.y, o.x, o.y)
                  , s = min(abs(r.colorHue - o.colorHue), 360 - abs(r.colorHue - o.colorHue));
                if (l < 15 && s < 20) {
                    i = !0,
                    t.push({
                        targetPos: `(${o.x}, ${o.y})`,
                        targetHue: o.colorHue,
                        particlePos: `(${Math.floor(r.x)}, ${Math.floor(r.y)})`,
                        particleHue: r.colorHue,
                        distance: Math.floor(l),
                        hueDifference: Math.floor(s)
                    });
                    break
                }
            }
        i && e++
    }
    e >= 7 && (flagRevealed = !0,
    console.log("\uD83C\uDF89 All positions correct! Retrieving flag..."),
    retrieveFlag())
}
function mousePressed() {
    isMousePressed = !0
}
function mouseReleased() {
    isMousePressed = !1
}
function keyPressed() {
    ("c" === key || "C" === key) && (particles = [],
    resetGrid())
}
function windowResized() {
    resizeCanvas(windowWidth, windowHeight),
    resetGrid()
}

```
so from that we can use injectSand(x, y, hue) lets us cheat the simulation by inject these payload in the browser console

```
[
  [367, 238, 0],
  [412, 293, 40],
  [291, 314, 60],
  [392, 362, 120],
  [454, 319, 240],
  [349, 252, 280],
  [433, 301, 320]
].forEach(([x, y, h]) => injectSand(x, y, h));
```

This function lets us: Place a particle exactly at x, y, Give it the exact hue needed. And finally gave us the flag:

![image](https://github.com/user-attachments/assets/1b17dcd8-bae8-43a4-a205-1f2c181c79d7)

```
flag{6ff0c72ad11bf174139e970559d9b5d2}
```

### TMCB

![Screenshot 2025-05-25 164726](https://github.com/user-attachments/assets/8de99c23-23ec-47ac-9901-a913eba42c37)

This challenge provided a frontend with 2,000,000 checkboxes and a WebSocket backend that tracks checked states server-side. The goal was to tick all 2 million checkboxes to reveal the flag.

![Screenshot 2025-05-25 165622](https://github.com/user-attachments/assets/31cb9004-1571-42db-9323-7e229466d8d1)

From this static/js/main.js
```js
document.addEventListener('DOMContentLoaded', () => {
    // Use native WebSocket
    let ws;
    let checkedBoxes = new Set();
    const TOTAL_CHECKBOXES = 2_000_000;
    const CHECKBOXES_PER_PAGE = 1000; // Smaller chunks for smoother loading
    let currentPage = 0;
    let isLoading = false;
    let hasMoreCheckboxes = true;
    
    const checkboxGrid = document.getElementById('checkbox-grid');
    const checkedCount = document.getElementById('checked-count');
    const flagContainer = document.getElementById('flag-container');
    const flagElement = document.getElementById('flag');
    const loadingOverlay = document.querySelector('.loading-overlay');
    const content = document.querySelector('.content');
    
    // Server-side state
    const SERVER_FLAG = window.SERVER_FLAG;
    const ALL_CHECKED = window.ALL_CHECKED;
    
    // If server says all checkboxes are checked, show flag immediately
    if (ALL_CHECKED && SERVER_FLAG) {
        showFlagDialog();
    }
    
    function connectWebSocket() {
        ws = new WebSocket('ws://' + window.location.host + '/ws');
        
        ws.onopen = function() {
            // Request initial state when connection is established
            ws.send(JSON.stringify({ action: 'get_state' }));
        };
        
        ws.onmessage = function(event) {
            const data = JSON.parse(event.data);
            if (data.checked) {
                try {
                    // Decode base64
                    const decoded = atob(data.checked);
                    // Convert to Uint8Array for pako
                    const compressed = new Uint8Array(decoded.length);
                    for (let i = 0; i < decoded.length; i++) {
                        compressed[i] = decoded.charCodeAt(i);
                    }
                    // Decompress using pako
                    const decompressed = pako.inflate(compressed, { to: 'string' });
                    // Parse JSON
                    const checkboxList = JSON.parse(decompressed);
                    
                    checkedBoxes = new Set(checkboxList);
                    updateUI();
                    
                    // Hide loading overlay and show content
                    if (loadingOverlay) {
                        loadingOverlay.style.display = 'none';
                    }
                    if (content) {
                        content.classList.add('loaded');
                    }
                    
                    // Load initial batch of checkboxes
                    loadMoreCheckboxes();
                } catch (e) {
                    console.error('Error processing compressed data:', e);
                }
            }
            if (data.error) {
                console.error('WebSocket error:', data.error);
            }
        };

        ws.onclose = function() {
            console.log('WebSocket closed, reconnecting...');
            setTimeout(connectWebSocket, 1000);
        };
    }

    function updateUI() {
        document.getElementById('checked-count').textContent = checkedBoxes.size.toLocaleString();
        
        // Show flag dialog if all checkboxes are checked
        if (checkedBoxes.size === TOTAL_CHECKBOXES && SERVER_FLAG) {
            showFlagDialog();
        } else {
            // Hide flag if not all checkboxes are checked
            flagContainer.style.display = 'none';
        }
    }

    function showFlagDialog() {
        flagElement.textContent = SERVER_FLAG;
        flagContainer.style.display = 'block';
        
        // Trigger confetti
        confetti({
            particleCount: 100,
            spread: 70,
            origin: { y: 0.6 }
        });
    }

    function loadMoreCheckboxes() {
        if (isLoading || !hasMoreCheckboxes) return;
        
        isLoading = true;
        const start = currentPage * CHECKBOXES_PER_PAGE;
        const end = Math.min(start + CHECKBOXES_PER_PAGE, TOTAL_CHECKBOXES);
        
        // Create a document fragment for better performance
        const fragment = document.createDocumentFragment();
        
        for (let i = start; i < end; i++) {
            const checkboxContainer = document.createElement('div');
            checkboxContainer.className = 'checkbox-container';
            
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.id = `checkbox-${i}`;
            checkbox.checked = checkedBoxes.has(i);
            
            checkbox.addEventListener('change', function() {
                const numbers = [i];
                if (this.checked) {
                    ws.send(JSON.stringify({
                        action: 'check',
                        numbers: numbers
                    }));
                } else {
                    ws.send(JSON.stringify({
                        action: 'uncheck',
                        numbers: numbers
                    }));
                }
            });
            
            checkboxContainer.appendChild(checkbox);
            fragment.appendChild(checkboxContainer);
        }
        
        // Append all new checkboxes at once
        checkboxGrid.appendChild(fragment);
        
        currentPage++;
        isLoading = false;
        
        // Check if we've reached the end
        if (end >= TOTAL_CHECKBOXES) {
            hasMoreCheckboxes = false;
        }
    }

    // Initial setup
    connectWebSocket();

    // Handle page navigation with debouncing
    let scrollTimeout;
    window.addEventListener('scroll', function() {
        if (scrollTimeout) {
            clearTimeout(scrollTimeout);
        }
        
        scrollTimeout = setTimeout(function() {
            const scrollPosition = window.scrollY;
            const windowHeight = window.innerHeight;
            const documentHeight = document.documentElement.scrollHeight;
            
            // Load more when user is near the bottom
            if (scrollPosition + windowHeight >= documentHeight - 500) {
                loadMoreCheckboxes();
            }
        }, 100); // Debounce scroll events
    });
}); 
```
The challenge relied on client-side checkbox interactions, but used WebSocket messages to actually track progress on the server.

This means: you didn’t have to click UI checkboxes, you only needed to send the right messages. The WebSocket accepted raw JSON messages with no authentication, rate-limiting, or replay protection and anyone could: **Connect directly, Forge messages or even Automate the interaction**

We scripted (by vibe-coding) a solution in the browser’s console that:

![image](https://github.com/user-attachments/assets/fee821f5-009f-4c10-833b-5407491694ad)

- Sent batches of 20,000 checkbox indices
- Used localStorage to track progress
- Automatically resumed if interrupted
- After sending all 2 million, the server would respond with the flag or set it in window.SERVER_FLAG

```js
let ws;
let index = parseInt(localStorage.getItem("progress") || "0", 10);
const total = 2_000_000;
const batchSize = 20000;
const delay = 250;
let reconnectAttempts = 0;

function connectWebSocket() {
  ws = new WebSocket("ws://" + window.location.host + "/ws");

  ws.onopen = () => {
    console.log(`✅ Connected. Resuming at index ${index}`);
    reconnectAttempts = 0;
    sendNextBatch();
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.flag) {
        console.log("🎉 FLAG:", data.flag);
        alert("🎉 FLAG: " + data.flag);
      } else {
        console.log("📩 Server response:", data);
      }
    } catch (e) {
      console.warn("⚠️ Non-JSON message:", event.data);
    }
  };

  ws.onclose = () => {
    console.warn("❌ WebSocket closed. Reconnecting...");
    reconnectAttempts++;
    const backoff = Math.min(2000 * reconnectAttempts, 10000);
    setTimeout(connectWebSocket, backoff);
  };

  ws.onerror = (err) => {
    console.error("🚨 WebSocket error:", err);
    ws.close();
  };
}

function sendNextBatch() {
  if (ws.readyState !== WebSocket.OPEN) {
    console.warn("⚠️ WebSocket not open. Skipping batch.");
    return;
  }

  if (index >= total) {
    console.log("✅ All 2 million checkboxes sent!");
    return;
  }

  const numbers = [];
  for (let i = index; i < Math.min(index + batchSize, total); i++) {
    numbers.push(i);
  }

  ws.send(JSON.stringify({ action: "check", numbers }));
  localStorage.setItem("progress", index);

  if (index % 100000 === 0) {
    console.log(`📦 Progress: ${index.toLocaleString()} / ${total.toLocaleString()}`);
  }

  console.log(`✅ Sent ${numbers.length} checkboxes: ${index} to ${index + numbers.length - 1}`);
  index += batchSize;

  setTimeout(sendNextBatch, delay);
}

connectWebSocket();
```

![Screenshot 2025-05-25 165654](https://github.com/user-attachments/assets/4c80670c-0054-4a91-8470-f5854744cbc9)

But, Due to network or timing issues, some final batches didn’t register. We resolved this by reset our progress in local storage and replaying the final 100,000 checkboxes and manually triggering a state check.

```js
const ws2 = new WebSocket("ws://" + window.location.host + "/ws");

ws2.onopen = () => {
  const numbers = [];
  for (let i = 1980000; i < 2000000; i++) {
    numbers.push(i);
  }

  ws2.send(JSON.stringify({
    action: "check",
    numbers
  }));

  console.log("✅ Final batch sent: 1,980,000 to 1,999,999");

  setTimeout(() => {
    ws2.send(JSON.stringify({ action: "get_state" }));
  }, 500);
};

ws2.onmessage = (event) => {
  try {
    const data = JSON.parse(event.data);
    console.log("📩 Server says:", data);
    if (data.flag) {
      alert("🎉 FLAG: " + data.flag);
    }
  } catch (e) {
    console.warn("⚠️ Could not parse message:", event.data);
  }
};
```
Once the server verified all checkboxes were checked, it revealed the flag through the WebSocket or the DOM.

![Screenshot 2025-05-24 214523](https://github.com/user-attachments/assets/378188c5-4c2f-4e04-b432-69c6400f6ec4)

```
flag{7d798903eb2a1823803a243dde6e9d5b}
```
