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
// / This file contains the configuration entries of the ScanCore_Definitions application.
// / 
// / VERSION COMPATIBILITY ...
// / This file is a MINIMUM match against the builder.
// / A configuration file newer than the builder is accepted, because it carries every
// / setting the builder asks for & some it does not read yet.
// / A configuration file older than the builder is refused, because a setting the
// / builder now depends upon may simply not be in it.
// / 
// / <3 Open-Source
// / -----------------------------------------------------------------------------------



// / -----------------------------------------------------------------------------------
// / Directory locations ...
// / 
// /  --Repository Root--
// /   The absolute path of the ScanCore_Definitions working copy.
// /   Default is the folder above the one holding this file.
$DefsRepoRoot = realpath(dirname(dirname(__FILE__)));
// /  --Sources Directory--
// /   Where a raw downloaded feed is kept, exactly as it arrived.
// /   A build is reproducible from what is committed here, & a feed that turns out to
// /   be publishing rubbish can be traced afterwards rather than argued about.
// /   Default is 'Sources'.
$DefsSourceDirName = 'Sources';
// /  --Local Directory Name--
// /   The folder name used for anything that may not be redistributed.
// /   This name is used underneath the sources directory & at the repository root, &
// /   both are ignored by git. Committing the raw download of a feed we may not
// /   republish would redistribute it as surely as committing the built file would.
// /   Default is 'Local'.
$DefsLocalDirName = 'Local';
// /  --Recipes Directory--
// /   Where a recipe lives. One file per source, describing where to fetch it, how to
// /   read it & what it may become.
// /   Default is 'Recipes'.
$DefsRecipeDirName = 'Recipes';
// /  --Policy Directory--
// /   Where the build policy lives.
// /   Default is 'Policy'.
$DefsPolicyDirName = 'Policy';
// /  --Limits File Name--
// /   The policy file naming the length, variety & count limits an indicator must pass.
// /   Default is 'limits.txt'.
$DefsLimitsFileName = 'limits.txt';
// /  --Allowlist File Name--
// /   The policy file naming values that may never become an indicator.
// /   Default is 'allowlist.txt'.
$DefsAllowlistFileName = 'allowlist.txt';
// /  --Build Report File Name--
// /   Where the build writes an account of everything it refused, changed or could not
// /   do. A silent refusal is how a feed quietly stops contributing & nobody notices.
// /   Default is 'BUILD_REPORT.txt'.
$DefsBuildReportFileName = 'BUILD_REPORT.txt';
// /  --Output File Prefix--
// /   The prefix of a built definition file. A category name & the .def extension are
// /   appended, producing names such as ScanCore_Virus.def.
// /   ScanCore downloads these by name, so changing this needs a matching change to
// /   the definition subscriptions in ScanCore_Config.php.
// /   Default is 'ScanCore_'.
$DefsOutputPrefix = 'ScanCore_';
// /  --Staging Suffix--
// /   Appended to a file being downloaded, so a partial download never replaces a
// /   committed source.
// /   Default is '.new'.
$DefsStagingSuffix = '.new';
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / Fetch behaviour ...
// / 
// /  --Fetch Timeout--
// /   Number of seconds to wait for a feed before giving up on it.
// /   Must be formatted as an integer, or an equation that evaluates to an integer.
// /   Default is 60.
$DefsFetchTimeout = 60;
// /  --User Agent--
// /   The user agent this application presents when fetching a feed. Several providers
// /   ask that an automated consumer identify itself, & a provider that needs to reach
// /   you about a misbehaving client has nothing else to go on.
// /   Must be formatted as a string.
$DefsUserAgent = 'ScanCore-Definitions-Builder';
// /  --Follow Redirects--
// /   Follow an HTTP redirect while fetching a feed. Several providers redirect an
// /   export endpoint to a content delivery host.
// /   Valid options are TRUE or FALSE.
// /   Default is TRUE.
$DefsFollowRedirects = TRUE;
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / Version information ...
// / 
// /  --Configuration Version--
// /   The version of this file, used for internal version integrity checks.
// /   Must be formatted as a string.
// /   Must be equal to or newer than the scancore-defs.php file.
$DefsConfigVersion = 'v1.8';
// / -----------------------------------------------------------------------------------
