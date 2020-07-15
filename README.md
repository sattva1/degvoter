# degvoter
#### degvoter that doesn't suck [so much]

The proper PoC implementation of a garbage voter national ID verification tool [discovered and documented](https://meduza.io/feature/2020/07/09/vlasti-fakticheski-vylozhili-v-otkrytyy-dostup-personalnye-dannye-vseh-internet-izbirateley) by Meduza.io. The implementation is based on ideas layed out in [Twitter thread](https://twitter.com/__sattva/status/1281655790944899072) as well as [suggested](https://twitter.com/efedin_ru/status/1281667607373000706) by Evgeny Fedin. It is a personal project made for fun in a few spare hours, tune your expectations accordingly.

Unlike the original implementation (by the DIT of Moscow) which stored passport ID hashes in a SQL database, we are employing two Bloom filters:

  - Voters (regular, high false positives rate)
  - NonVoters (counting, low false positives rate)

Both filters are initialized up to the total number of voters eligible for the e-voting. When a voter registers for the e-voting, their passport ID hash is stored into the NonVoters filter; then, once an electronic ballot is casted, the passport ID hash is removed from the NonVoters filter and added to the Voters filter. (At the end of the e-voting period
the union of both filters should represent a cohort of all the voters registered for the e-voting, regardless of whether they participated in the procedure or not.)

To determine whether a voter is eligible for a traditional paper ballot voting (i.e. if he/she opted out of e-voting by not casting an electronic ballot after registering), the following steps are performed:

- Check Voters filter for a passport ID.
  - If match (probabilistic) check NonVoters filter for a passport ID.
    - If match (probabilistic) -> voter is eligible.
    - Else (deterministic) -> voter is ineligible.
  - Else (deterministic) -> voter is eligible.

This ensures the following requirements are met:
  - An eligible voter must not be refused to vote;
  - An ineligible voter may have a low chance for a double vote.
The latter is deemed acceptable since a voter cannot know in advance their passport ID check would match false positive, and the chance is configurable with the NonVoters filter false positives rate.

In order to protect against brute force hash preimage attacks to recover all passport IDs (the bane of the original degvoter implementation which lacked any protection due to plain hashing of ID values), Argon2 KDF along with a salt is used to slow down verification attempts. However instead of a random unique salt value per passport ID, the current PoC follows a non-standard approach: a passport issue date is used for the salt value instead. A rationale for this is the following. Although there are certain biases, it is presumed the passport numbers are distributed evenly enough over the issue date range; passport numbers are not directly correlated with issue dates since numbers are a [simple cyclic counter](https://habr.com/ru/company/hflabs/blog/478538/). According to the [analysis](https://meduza.io/feature/2020/07/09/vlasti-fakticheski-vylozhili-v-otkrytyy-dostup-personalnye-dannye-vseh-internet-izbirateley) of the leaked database, there were at most 100k passports issued in any year, or roughly 275 (2^8.1) per day on average. The practical entropy of an issue date is less than anticipated since the year of a passport issue can be deduced with certain precision ([roughly
+/- 3 years](https://habr.com/ru/company/hflabs/blog/478538/)) from the ID (its serial number part); this leaves us with
slightly over 2^8.5 bits of entropy which is on par with the max number of IDs issued in a day, hence deemed enough (albeit at the lower boundary) for protection against exhaustive search attacks.
