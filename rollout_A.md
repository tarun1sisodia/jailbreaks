# webprobe Security Report - https://agraskbagheltourandtravels.com
- **Profile:** recon
- **Duration:** 61.17s
- **Total Findings:** 70

## [INFO] robots.txt exposed
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/robots.txt
- **Evidence:** 1223 bytes; disallowed: /, /book.html, /book, /book/, /book*, /404.html, /design-guide/, /
- **Remediation:** robots.txt is not access control; protect sensitive paths with authentication.

## [INFO] sitemap exposed
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/sitemap.xml
- **Evidence:** 71 urls; first: https://agraskbagheltourandtravels.com/
- **Remediation:** Ensure sitemap does not enumerate sensitive URLs.

## [INFO] security.txt present
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/.well-known/security.txt
- **Evidence:** contacts: 1; policy: https://agraskbagheltourandtravels.com/en/contact/; expires: 2027-10-01T00:00:00.000Z
- **Remediation:** Keep the file current and within its Expires window.

## [INFO] Infrastructure headers exposed
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com
- **Evidence:** CF-Ray: a553869ae95c9788-DEL
- **Remediation:** Strip hop-by-hop and CDN-internal headers at the edge.

## [MEDIUM] CSP does not restrict inline script
- **Category:** csp
- **URL:** https://agraskbagheltourandtravels.com
- **Evidence:** Issues: unsafe-inline without nonce; CSP: default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' https://www.googletagmanager.com https://*.googletagmanager.com https://stati...
- **Remediation:** Remove 'unsafe-inline' and 'unsafe-eval'; enforce nonces.

## [INFO] External host referenced in JS: www.w3.org
- **Category:** recon
- **URL:** http://www.w3.org/2000/svg
- **Evidence:** referenced from a client bundle
- **Remediation:** Confirm non-public hosts are not reachable and do not expose internal APIs.

## [INFO] External host referenced in JS: api.agraskbagheltourandtravels.com
- **Category:** recon
- **URL:** https://api.agraskbagheltourandtravels.com/api/v1/tour-packages/media/50c4be58-45fe-43d5-8056-7438e1aefad4.jpg
- **Evidence:** referenced from a client bundle
- **Remediation:** Confirm non-public hosts are not reachable and do not expose internal APIs.

## [INFO] External host referenced in JS: api.agraskbagheltourandtravels.com
- **Category:** recon
- **URL:** https://api.agraskbagheltourandtravels.com/api/v1/tour-packages/media/baba62e7-3e42-4122-922d-[REDACTED:phone_intl:17…98:hee386898]fd9.webp
- **Evidence:** referenced from a client bundle
- **Remediation:** Confirm non-public hosts are not reachable and do not expose internal APIs.

## [INFO] External host referenced in JS: api.agraskbagheltourandtravels.com
- **Category:** recon
- **URL:** https://api.agraskbagheltourandtravels.com/api/v1/tour-packages/media/e9fbf686-41a1-4773-b6e6-b8cb7bca7b4e.webp
- **Evidence:** referenced from a client bundle
- **Remediation:** Confirm non-public hosts are not reachable and do not expose internal APIs.

## [INFO] External host referenced in JS: commons.wikimedia.org
- **Category:** recon
- **URL:** https://commons.wikimedia.org/wiki/File:Agra_03-2016_14_Agra_Fort.jpg
- **Evidence:** referenced from a client bundle
- **Remediation:** Confirm non-public hosts are not reachable and do not expose internal APIs.

## [INFO] External host referenced in JS: commons.wikimedia.org
- **Category:** recon
- **URL:** https://commons.wikimedia.org/wiki/File:All_India_War_Memorial_(INDIA_GATE).jpg
- **Evidence:** referenced from a client bundle
- **Remediation:** Confirm non-public hosts are not reachable and do not expose internal APIs.

## [INFO] External host referenced in JS: commons.wikimedia.org
- **Category:** recon
- **URL:** https://commons.wikimedia.org/wiki/File:DASHASHWAMEDH_GHAT,_VARANASI.jpg
- **Evidence:** referenced from a client bundle
- **Remediation:** Confirm non-public hosts are not reachable and do not expose internal APIs.

## [INFO] External host referenced in JS: commons.wikimedia.org
- **Category:** recon
- **URL:** https://commons.wikimedia.org/wiki/File:Fatehpur_Sikri_near_Agra_2016-03_img08.jpg
- **Evidence:** referenced from a client bundle
- **Remediation:** Confirm non-public hosts are not reachable and do not expose internal APIs.

## [INFO] External host referenced in JS: commons.wikimedia.org
- **Category:** recon
- **URL:** https://commons.wikimedia.org/wiki/File:Hamandir_Sahib_(Golden_Temple).jpg
- **Evidence:** referenced from a client bundle
- **Remediation:** Confirm non-public hosts are not reachable and do not expose internal APIs.

## [INFO] External host referenced in JS: commons.wikimedia.org
- **Category:** recon
- **URL:** https://commons.wikimedia.org/wiki/File:Hawa_Mahal_Day_View.jpg
- **Evidence:** referenced from a client bundle
- **Remediation:** Confirm non-public hosts are not reachable and do not expose internal APIs.

## [INFO] External host referenced in JS: commons.wikimedia.org
- **Category:** recon
- **URL:** https://commons.wikimedia.org/wiki/File:Houseboat_at_Kerala_Backwaters.jpg
- **Evidence:** referenced from a client bundle
- **Remediation:** Confirm non-public hosts are not reachable and do not expose internal APIs.

## [INFO] External host referenced in JS: commons.wikimedia.org
- **Category:** recon
- **URL:** https://commons.wikimedia.org/wiki/File:Jaipur_03-2016_02_Amber_Fort.jpg
- **Evidence:** referenced from a client bundle
- **Remediation:** Confirm non-public hosts are not reachable and do not expose internal APIs.

## [INFO] External host referenced in JS: commons.wikimedia.org
- **Category:** recon
- **URL:** https://commons.wikimedia.org/wiki/File:Solang_Valley_,Manali,_Himachal_Pardes,_India.JPG
- **Evidence:** referenced from a client bundle
- **Remediation:** Confirm non-public hosts are not reachable and do not expose internal APIs.

## [INFO] External host referenced in JS: commons.wikimedia.org
- **Category:** recon
- **URL:** https://commons.wikimedia.org/wiki/File:Taj_Mahal_on_a_bright_sunny_day.jpg
- **Evidence:** referenced from a client bundle
- **Remediation:** Confirm non-public hosts are not reachable and do not expose internal APIs.

## [INFO] External host referenced in JS: maps.google.com
- **Category:** recon
- **URL:** https://maps.google.com/?q=1Nandlalpur%2C+Hathras+Rd%2C+near+Khusum%2C+Nagla%2C+Agra%2C+Uttar+Pradesh+282006
- **Evidence:** referenced from a client bundle
- **Remediation:** Confirm non-public hosts are not reachable and do not expose internal APIs.

## [INFO] External host referenced in JS: maps.google.com
- **Category:** recon
- **URL:** https://maps.google.com/?q=Taj+Ganj%2C+Agra%2C+Uttar+Pradesh+282001
- **Evidence:** referenced from a client bundle
- **Remediation:** Confirm non-public hosts are not reachable and do not expose internal APIs.

## [INFO] External host referenced in JS: schema.org
- **Category:** recon
- **URL:** https://schema.org/${a.offers.availability||
- **Evidence:** referenced from a client bundle
- **Remediation:** Confirm non-public hosts are not reachable and do not expose internal APIs.

## [INFO] External host referenced in JS: wa.me
- **Category:** recon
- **URL:** https://wa.me/${C.whatsapp}
- **Evidence:** referenced from a client bundle
- **Remediation:** Confirm non-public hosts are not reachable and do not expose internal APIs.

## [INFO] External host referenced in JS: wa.me
- **Category:** recon
- **URL:** https://wa.me/${C.whatsapp}?text=Hello%20Agra%20SK%20Baghel%20Tour%20and%20Travels
- **Evidence:** referenced from a client bundle
- **Remediation:** Confirm non-public hosts are not reachable and do not expose internal APIs.

## [INFO] External host referenced in JS: wa.me
- **Category:** recon
- **URL:** https://wa.me/${C.whatsapp}?text=Hello%20Agra%20SK%20Baghel%20Tour%20and%20Travels,%20I%20would%20like%20to%20inquire%20about%20a%20booking.
- **Evidence:** referenced from a client bundle
- **Remediation:** Confirm non-public hosts are not reachable and do not expose internal APIs.

## [INFO] Endpoint disclosed in JavaScript: /404/
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/404/
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /api/
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/api/
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /api/v1/bookings
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/api/v1/bookings
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /api/v1/bookings/${a}
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/api/v1/bookings/${a}
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /api/v1/bookings/${a}/payment
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/api/v1/bookings/${a}/payment
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /api/v1/bookings/${a}/verify-payment
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/api/v1/bookings/${a}/verify-payment
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /api/v1/catalog
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/api/v1/catalog
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /api/v1/catalog/${a}/${t}
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/api/v1/catalog/${a}/${t}
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /api/v1/quotes/options
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/api/v1/quotes/options
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /assets/booking/taj-mahal-480.avif
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/assets/booking/taj-mahal-480.avif
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /assets/home-hero/${a}-1280.avif
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/assets/home-hero/${a}-1280.avif
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /assets/home-hero/${a}-1600.avif
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/assets/home-hero/${a}-1600.avif
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /assets/home-hero/${a}-480.avif
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/assets/home-hero/${a}-480.avif
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /assets/home-hero/${a}-960.avif
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/assets/home-hero/${a}-960.avif
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /auth/callback
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/auth/callback
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /auth/callback/
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/auth/callback/
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /auth/login
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/auth/login
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /booking/confirmation
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/booking/confirmation
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /booking/confirmation.html
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/booking/confirmation.html
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /cookie-policy/
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/cookie-policy/
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /en/
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/en/
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /en/${o.en}/
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/en/${o.en}/
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /en/about/
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/en/about/
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /en/book
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/en/book
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /en/contact/
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/en/contact/
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /en/faq/
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/en/faq/
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /en/fleet/
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/en/fleet/
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /en/home/
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/en/home/
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /en/monuments
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/en/monuments
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /en/monuments/
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/en/monuments/
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /en/packages/
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/en/packages/
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /en/privacy
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/en/privacy
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /en/rent
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/en/rent
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /en/rental
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/en/rental
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /en/routes/
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/en/routes/
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /en/services/
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/en/services/
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /en/taxi-rental
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/en/taxi-rental
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /en/taxis/rent
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/en/taxis/rent
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /en/taxis/rent/
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/en/taxis/rent/
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] Endpoint disclosed in JavaScript: /en/terms
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/en/terms
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] 21 top-level routes disclosed
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com
- **Evidence:** /404, /404.html, /book, /book.html, /booking, /booking-confirmation, /en, /fleet, /index.html, /login, /monuments, /my-bookings, /packages, /rent, /rental, /review, /routes, /services, /sw.js, /taxi-rental
- **Remediation:** Routes are public knowledge; ensure no privileged behaviour is reachable from the client alone.

## [INFO] Interesting path: /login
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/login/
- **Evidence:** HTTP 200, 42245 bytes, text/html
- **Remediation:** Remove or authenticate non-public paths; return a uniform 404 for everything else.

## [INFO] Interesting path: /robots.txt
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/robots.txt
- **Evidence:** HTTP 200, 1223 bytes, text/plain
- **Remediation:** Remove or authenticate non-public paths; return a uniform 404 for everything else.

## [INFO] Interesting path: /sitemap.xml
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/sitemap.xml
- **Evidence:** HTTP 200, 30788 bytes, application/xml
- **Remediation:** Remove or authenticate non-public paths; return a uniform 404 for everything else.

## [INFO] Interesting path: /.well-known/security.txt
- **Category:** recon
- **URL:** https://agraskbagheltourandtravels.com/.well-known/security.txt
- **Evidence:** HTTP 200, 237 bytes, text/plain
- **Remediation:** Remove or authenticate non-public paths; return a uniform 404 for everything else.

