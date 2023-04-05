---
layout: post
title: SAINTCON Minibadge Tester  
tags: [Hardware]
---


SAINTCON is a cybersecurity conference organized by the Utah Security Advisory and Incident Network Team. This conference offers a range of activities, including presentations, training sessions, games, challenges, and badge life. SAINTCON has established a standard for minibadges, which are small badges that can be added to your main badge. These minibadges have a clock pin, three ground pins, two 3v3 pins, and a VBATT pin.

Usually, minibadges consist of a tiny LED and a resistor. However, last year, I became interested in how these badges are created. SAINTCON encourages attendees to create their own minibadges and trade them with others. They even created a three-part tutorial on how to create a minibadge from scratch, which can be found here: [https://www.youtube.com/watch?v=kkLfmo14oiQ](https://www.youtube.com/watch?v=kkLfmo14oiQ).

I took on the challenge and started to learn KiCad and how to design little electronics. I created and ordered a handful of prototype badges that I wanted to bring to the conference. I tested them on my old badge from last year, which is very big and clunky due to all my modifications. However, I noticed that some people created their own badge testers, and SAINTCON even sold some in the past.

Therefore, I decided to create my own badge tester and design a more complex PCB/circuit. I wanted to mimic a real badge as much as possible so that my minibadges would work as I designed them. I chose to use a Pico Pi to power the badge. In KiCad, I mapped the ground pins and 3v pins to the corresponding pins for the Pico. I also mapped the clock pin to a GPIO pin to toggle power on and off (the real badge toggles ground and 3v). The minibadge also has eight pins that are not generally used, but I mapped them to GPIO pins so that I can use them for future projects.

It was a really fun project, and I put the KiCad files on my GitHub. Below are some pictures of the final product with two badges that I will bring to the 2023 SAINTCON.

https://github.com/0xZon/SAINTCON-Dev-Board

![front.jpg](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/miniBadgeTester/front.jpg)

![back.jpg](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/miniBadgeTester/back.jpg)

![front_w_badge.jpg](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/miniBadgeTester/front_w_badge.jpg)

![front_w_badge2.jpg](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/miniBadgeTester/front_w_badge2.jpg)
