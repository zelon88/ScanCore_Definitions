<?php
// / -----------------------------------------------------------------------------------
// / COPYRIGHT INFORMATION ...
// / ScanCore_Definitions, Copyright on 9/3/2026 by Justin Grimes, www.github.com/zelon88
// / 
// / LICENSE INFORMATION ...
// / This project is protected by the GNU GPLv3 Open-Source license.
// / BSD or MIT licensing is available. Reach out to @zelon88 for more information.
// / https://www.gnu.org/licenses/gpl-3.0.html
// / 
// / APPLICATION INFORMATION ...
// / This application collects raw threat feeds & builds them into ScanCore definitions.
// / 
// / FILE INFORMATION ...
// / v1.8.
// / This file contains the version manifest of the ScanCore_Definitions application.
// / 
// / WHY THIS FILE EXISTS ...
// / The builder, the configuration & this manifest are released together & are checked
// / against each other before any work begins. A half applied update leaves a builder
// / reading a configuration that does not carry the settings it expects, which produces
// / a definition file that looks correct & is not. Refusing to start is cheaper.
// / 
// / This manifest is an EXACT match against the builder. A builder & a manifest that
// / disagree are two halves of different releases.
// / 
// / VERSION COMPATIBILITY ...
// / Compare version numbers numerically, never as strings.
// / A string comparison ranks 24.2 below 7.6 & ranks 3.10 below 3.9.
// / 
// / <3 Open-Source
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / Version information ...
// / 
// /  --Definitions Version--
// /   The version of the ScanCore_Definitions application as a whole.
// /   Must be formatted as a string. Must match the scancore-defs.php file exactly.
$DefsVersion = 'v1.8';
// /  --Definition Format Version--
// /   The version of the definition grammar this builder writes.
// /   ScanCore reads this from the header of a built definition file to know whether it
// /   understands the grammar in front of it. Raise this only when the grammar changes
// /   in a way an older ScanCore could not read, which is not the same as raising the
// /   application version.
// /   Must be formatted as a string.
$DefsFormatVersion = 'v1.8';
// /  --Project Name--
// /   The name this application stamps into the files it produces.
// /   Must be formatted as a string.
$DefsProjectName = 'ScanCore_Definitions';
// /  --Repository URL--
// /   The home of this application, recorded in the header of every file it builds.
// /   Must be formatted as a string.
$DefsRepositoryURL = 'https://github.com/zelon88/ScanCore_Definitions';
// / -----------------------------------------------------------------------------------
