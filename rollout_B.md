# webprobe Security Report - https://agraskbagheltourandtravels.com
- **Profile:** owasp
- **Duration:** 117.97s
- **Total Findings:** 32

## [INFO] Server technology banners disclosed
- **Category:** headers
- **URL:** https://agraskbagheltourandtravels.com
- **Evidence:** Server: cloudflare
- **Remediation:** Disable or strip Server and X-Powered-By response headers in reverse proxy configuration.

## [LOW] Authenticated response missing Cache-Control: no-store
- **Category:** session
- **URL:** https://agraskbagheltourandtravels.com
- **Evidence:** Cache-Control: unset
- **Remediation:** Set 'Cache-Control: no-store, private' on all authenticated pages.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book.html
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book.html?category=local_package&amp;product=agra-tour-for-international-tourists-full-day&amp;from=Agra&amp;to=Agra%20Tour%20for%20International%20Tourists%20Full%20Day
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book.html?category=outstation&amp;car=ertiga
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book.html?category=outstation&amp;car=innova
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book.html?category=outstation&amp;car=luxury
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book.html?category=outstation&amp;car=sedan
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book.html?category=outstation&amp;car=tempo
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book.html?category=outstation&amp;car=urbania
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book.html?category=tour_package&amp;product=agra-sightseeing&amp;from=Agra&amp;to=Same%20Day%20Agra%20Taj%20Mahal%20Tour
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book.html?category=tour_package&amp;product=agra-unhurried&amp;from=Agra&amp;to=Agra%20Overnight%20Experience
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book.html?category=tour_package&amp;product=exclusive-tour-of-agra-for-1-day&amp;from=Agra&amp;to=Agra%2C%20Agra%2C%20Uttar%20Pradesh
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book.html?category=tour_package&amp;product=gatimaan-express-agra-tour&amp;from=Agra&amp;to=Same%20Day%20Agra%20by%20Gatimaan%20Train
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book.html?category=tour_package&amp;product=golden-triangle&amp;from=Agra&amp;to=Golden%20Triangle%20Tour
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book.html?category=tour_package&amp;product=mathura-vrindavan&amp;from=Agra&amp;to=Mathura%20%26%20Vrindavan%20Darshan
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book.html?category=tour_package&amp;product=same-day-agra-to-mathura-tour&amp;from=Agra&amp;to=Mathura%2C%20Mathura%2C%20Uttar%20Pradesh
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book.html?category=tour_package&amp;product=taj-mahal-sunrise-tour&amp;from=Agra&amp;to=Taj%20Mahal%20Sunrise%20Tour
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book/
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book?category=local
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book?category=local_package&amp;product=agra-12h-city
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book?category=local_package&amp;product=agra-8h-80km
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book?category=outstation
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book?category=tour
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book?category=transfer
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book?category=transfer&amp;product=agra-cantt-to-hotel
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book?category=transfer&amp;product=delhi-igi-airport
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/book?category=transfer&amp;product=kheria-airport-transfer
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

## [HIGH] Endpoint reachable unauthenticated AND authenticated
- **Category:** authz
- **URL:** https://agraskbagheltourandtravels.com/cookie-policy/
- **Evidence:** anon HTTP 200; customer HTTP 200
- **Remediation:** Require authentication on non-public endpoints; enforce ownership checks on every resource.

