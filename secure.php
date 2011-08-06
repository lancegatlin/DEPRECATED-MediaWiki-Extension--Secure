<?php

$wgExtensionFunctions[] = 'wfSecure';

/* register parser hook */
$wgExtensionCredits['parserhook'][] = array(
    'name' => 'secure',
    'author' => 'Lance Gatlin',
    'version' => '20MAY09',
);

define( 'SECURE2_TAG' , 'secure2' );
define( 'SECURE_TAG' , 'secure' );
define( 'NOACCESS_TAG', 'noaccess' );
define( 'OWNER_ATTR', 'owner' );
define( 'ANYONE_ATTR', 'anyone' );
define( 'READ_ATTR', 'read');
define ('GROUP_ATTR', 'group');
define ('GROUPTEXT_ATTR', 'text');
define ('METHOD_ATTR', 'method');
define ('SECURE_CORRUPT_ERROR_MSG', 'SECURE_DATA_CORRUPT');
define ('NOWIKI_TAG', 'nowiki');	
define ('PRE_TAG', 'pre');	

/*function dout($t)
{
	$f = fopen('extensions/secure.txt', 'a+t');
	if(f === false)
		reutrn;
	
	fwrite($f, $t);
	fclose($f);
}*/

/**
 * Extension-function. Registers parser, hook
 */
function wfSecure() {
    global $wgHooks, $gReplaceOnSaveHook, $gSecureParseTags, $wgParser;

	$gSecureParseTags[] = 'pre';
	$gSecureParseTags[] = 'nowiki';
	
	// Hook SecureEdit to decrypt secure contents for authorized users or noaccess message for anyone else
	$wgHooks['AlternateEdit'][] = 'Secure_AlternateEdit';
	// Hook ArticleSave to encrypt secure blocks
//	$gReplaceOnSaveHook[SECURE_TAG] = 'Secure_ReplaceSecureOnSave';
	Secure_RegisterTag(SECURE_TAG, 'Secure_SecureTagHook');
	Secure_RegisterTag(SECURE2_TAG, 'Secure_Secure2TagHook');
	
	$gReplaceOnSaveHook[NOACCESS_TAG] = 'Secure_ReplaceNoAccessOnSave';

	// Hook  ParserBeforeStrip to decrypt secure blocks for authorized users
	$wgHooks['ParserBeforeStrip'][] = 'Secure_ParserBeforeStrip';
//	$wgHooks['ArticleAfterFetchContent'][] = 'Secure_ArticleAfterFetchContent';
}

function Secure_RegisterTag($tag, $handler)
{
	global $gReplaceOnSaveHook, $gSecureTagHook, $gSecureParseTags;
	
	$gReplaceOnSaveHook[$tag] = 'Secure_ReplaceSecureTagOnSave';
	$gSecureTagHook[$tag] = $handler;
	$gSecureParseTags[] = $tag;
}

// Same code from Sanitizer (1.7.3) This is private in sanitizier so must be repeated here
function Secure_getTagAttributeCallback( $set ) {
	if( isset( $set[6] ) ) {
		# Illegal #XXXXXX color with no quotes.
		return $set[6];
	} elseif( isset( $set[5] ) ) {
		# No quotes.
		return $set[5];
	} elseif( isset( $set[4] ) ) {
		# Single-quoted
		return $set[4];
	} elseif( isset( $set[3] ) ) {
		# Double-quoted
		return $set[3];
	} elseif( !isset( $set[2] ) ) {
		# In XHTML, attributes must have a value.
		# For 'reduced' form, return explicitly the attribute name here.
		return $set[1];
	} else {
//		throw new MWException( "Tag conditions not met. This should never happen and is a bug." );
	}
}

$secure_attrib='[A-Za-z0-9_-]';
$secure_space = '[\x09\x0a\x0d\x20]';
define( 'SECURE_MW_ATTRIBS_REGEX',
	"/(?:^|$secure_space)($secure_attrib+)
	  ($secure_space*=$secure_space*
		(?:
		 # The attribute value: quoted or alone
		  \"([^<\"]*)\"
		 | '([^<']*)'
		 |  ([a-zA-Z0-9!#$%&()*,\\-.\\/:;<>?@[\\]^_`{|}~]+)
		 |  (\#[0-9a-fA-F]+) # Technically wrong, but lots of
							 # colors are specified like this.
							 # We'll be normalizing it.
		)
	   )?(?=$secure_space|\$)/sx" );

// Same code from Sanitizer::decodeTagAttributes (1.7.3) modified so as not to force lower case parameters 
// changed this to support char references in case other tags need them
// and doesn't support
// decoding char references
function Secure_decodeTagAttributes( $text ) {
	$attribs = array();

	if( trim( $text ) == '' ) {
		return $attribs;
	}

	$pairs = array();
	if( !preg_match_all(
		SECURE_MW_ATTRIBS_REGEX,
		$text,
		$pairs,
		PREG_SET_ORDER ) ) {
		return $attribs;
	}

	foreach( $pairs as $set ) {
		//$attribute = strtolower( $set[1] );
		$attribute = $set[1];
//		$value = Sanitizer::getTagAttributeCallback( $set );
		$value = Secure_getTagAttributeCallback( $set );
		
		// Normalize whitespace
		$value = preg_replace( '/[\t\r\n ]+/', ' ', $value );
		$value = trim( $value );
		
		// Decode character references
		$attribs[$attribute] = Sanitizer::decodeCharReferences( $value );
		$attribs[$attribute] = $value;
	}
	return $attribs;
}

function Secure_ParseDecryptText($dectext)
{
	global $wgUser;

	// Parse parameter string  
	// users="Lance" Test="blah" anyone="access denied" group1="Rob,Josh" group1_text="blah" ... >content
	// users="Lance" Test="blah" anyone="access denied" group1="Rob,Josh" group1_text="blah" ... />
	$ep = strpos($dectext, '>');
	if($ep === false)
		return array();
	
	if($dectext[$ep-1] == '/')
		$paratext = substr($dectext, 0, $ep - 1);
	else $paratext = substr($dectext, 0, $ep);
	
	// Call secure version of this instead of Sanitizer:: to preserve case of keys for testing against user names
	$retv[1] = Secure_decodeTagAttributes($paratext);

	// set the content
	$retv[2] = substr($dectext, $ep + 1);

	if(!$wgUser->isAnon())
	{
		$ownerlist = strtr($retv[1][OWNER_ATTR], " ", "_");
		$ownerlist = explode(',', $ownerlist);
				
		// If user was in the owner's parameter list
		$user = $wgUser->getName();
		$user = strtr($user, " ", "_");

		$retv[0] = in_array($user, $ownerlist);
	}
	else
		$retv[0] = false;

	return $retv;
}

//function Secure_ArticleAfterFetchContent(&$article, &$text)
function Secure_ParserBeforeStrip(&$parser, &$text, &$strip_state)
{
	global $wgOut, $gSecureParseTags, $wgUser, $gSecureTagHook, $wgParser;

//	$title = $parser->getTitle()->getText();
//	dout("Secure_ParserBeforeStrip: $title\n");
	// Parse the text
	// Replaces all <secure></secure> in text with a unique id (and html comments) and returns the new text
	// Returns an array that contains information about the <secure> tags located
//	dout(print_r($gSecureParseTags, true));
	$ptext = Parser::extractTagsAndParams(
//					   array(SECURE_TAG, NOWIKI_TAG, PRE_TAG),
						$gSecureParseTags
						,$text
						,$matches );	
	
	foreach($matches as $k => $i)
	{
		
		$tag = $i[0];
		$content = $i[1];
		$params = $i[2];
		$fulltag = $i[3];
		// If the tag is a secure tag, i.e. <secure>
//		if ($tag == SECURE_TAG)
//		dout("Secure_ParserBeforeStrip parse: $fulltag\n");
		if(Secure_IsSecureTag($tag))
		{
			$changed = true;
			
			$enctext = $content;

			// Remove newlines from encrypted text added for readability on save
			$enctext = str_replace("\n", '', $enctext);

			// Ensure contents needs to be decrypted
			if(Secure_IsEncrypted($enctext))
			{
				// Decrypt data
				$dectext = Secure_Decrypt($enctext);
				
				// If decrypt didn't fail
				if($dectext !== false)
				{
					// Parse dectext tag attributes
					$pdt = Secure_ParseDecryptText($dectext);
					$pdt_userIsOwner = $pdt[0];
					$pdt_params = $pdt[1];
					$pdt_content = $pdt[2];
					//$dsptext = Secure_GetUserText($params);
					// Call the hooked handler
					
					$dsptext = call_user_func($gSecureTagHook[$tag], $pdt_userIsOwner, $pdt_content, $pdt_params, $parser);
//					dout("Secure_ParserBeforeStrip: dsptext=$dsptext\n");
				}
				else
				{
					// Decrypt failed, display corrupt data error message
					$dsptext = SECURE_CORRUPT_ERROR_MSG;
				}
			}
			else
			{
				// Unencrypted data in secure tag (possibly from no owner) invoke handler
				// as long as user isn't anonymous consider them an owner
				$dsptext = call_user_func($gSecureTagHook[$tag], !$wgUser->isAnon(), $content, $params, $parser);
//				$dsptext = $content;
			}
			
			// Replace the unique-key with the new display text
			$ptext = str_replace($k, $dsptext, $ptext);
		}
		else
		{
			// This match is an html comment or <nowiki> section, just replace with no changes
			$ptext = str_replace($k, $fulltag, $ptext);
		}
	}
	// If any changes to the input text occured
	if($changed == true)
	{
		// Then update the text to the new text
		$text = $ptext;
		
		// Disable caching if user is not anonymous since the page will change depending on who views it
//		if( $wgUser->getID() != 0)
		if( !$wgUser->isAnon())
			$parser->disableCache();
		//			$wgParser->disableCache();
		
		// No robots or search engines should index a page with secure content
			$wgOut->setRobotpolicy( 'noindex,nofollow' );
	}
	
	return true;
}

function Secure_IsSecureTag($tag)
{
	global $gSecureTagHook;
	
	return isset($gSecureTagHook[$tag]);
}

function Secure_AlternateEdit($editpage)
{
	global $gSecureParseTags;
	
	// Get the text of the article under edit
	$text = $editpage->mArticle->getContent();

	// Parse the text
	// Replaces all <secure></secure> in text with a unique id (and html comments) and returns the new text
	// Returns an array that contains information about the <secure> tags located
	$ptext = Parser::extractTagsAndParams(
//					   array(SECURE_TAG, NOWIKI_TAG, PRE_TAG),
						$gSecureParseTags
						,$text
						,$matches );	

	foreach($matches as $k => $i)
	{
		$tag = $i[0];
		$content = $i[1];
		$fulltag = $i[3];
		// If the tag is a secure tag, i.e. <secure>
//		if ($tag == SECURE_TAG)
		if(Secure_IsSecureTag($tag))
		{
			// Which secure block # we are in - for <noaccess> tags
			$n++;
			
			$enctext = $content;
			
			// Remove newlines from encrypted text added for readability on save
			$etext = str_replace("\n", '', $enctext);
			
			// Ensure contents needs to be decrypted
			if(Secure_IsEncrypted($etext))
			{
				// if no changes default to the fulltag
				$dsptext = $fulltag;
				
				// Decrypt data
				$dectext = Secure_Decrypt($etext);
				
				// If decrypt didn't fail
				if($dectext !== false)
				{
					// Parse dectext tag attributes
					$pdt = Secure_ParseDecryptText($dectext);
					$pdt_userIsOwner = $pdt[0];
					$pdt_params = $pdt[1];
					$pdt_content = $pdt[2];
					
					// Parse the user list
//					$userlist = explode(',', $pdt_owner);
							
					// If user was in the users parameter list
//					if(!isset($params[OWNER_ATTR]) || in_array($user, $userlist))
//					if(in_array($user, $userlist))
					if($pdt_userIsOwner)
					{
						$changed = true;
						$next2last = strlen($dectext) - 2;
						// If the next to last char is '/' then don't add closing tag
						if(	$next2last >= 0 
							&& $dectext[$next2last] == '/')
							$dsptext = "<$tag$dectext";
						else $dsptext = "<$tag$dectext</$tag>";
					}
					// User is not in the list, return only a noaccess tag (or encrypted text)
					else 
					{
						// If we are editing the current revision
						if($editpage->mArticle->getOldId() == 0)
						{
							$changed = true;
							// Use more convenient <noaccess #> tags instead of long encrypt tags
							$dsptext = '<' . NOACCESS_TAG . ' ' . $n . '/>';
						}
						// If editing an older revision then just give the user the full tag 
						// (Otherwise the <noaccess #/> won't line up with the current version)
						else 
						{
							//$dsptext = "<$tag>$enctext</$tag>";
							//$dsptext=$fulltag;
						}
					}
				}
				else
				{
					// Decrypt failed, display corrupt data error message
					$changed = true;
					$dsptext = SECURE_CORRUPT_ERROR_MSG;
				}
			}
			else
			{
				// Unencrypted data in secure tag ( possibly no owner) no changes
				//$dsptext = $fulltag;
			}

			// Replace the unique-key with the new display text
			$ptext = str_replace($k, $dsptext, $ptext);
		}
		else
		{
			// This match is an html comment or <nowiki> section, just replace with no changes
			$ptext = str_replace($k, $fulltag, $ptext);
		}
	}
	
	// If any changes to the input text occured, update the editpage text to the new text
	if($changed == true)
		$editpage->mArticle->mContent = $ptext;
		
	return true;

}

function Secure_ReplaceSecureTagOnSave($tag, $content, $params, $fulltag, $article, $user, $text, $summary, $minoredit, $watchthis, $sectionanchor)
{
	// If there are any attributes set OR content is NOT encrypted
	// If *owner is set* AND content is NOT already encrypted
//	if(count($params) || !Secure_IsEncrypted($content))
	if(isset($params[OWNER_ATTR]) && !Secure_IsEncrypted($content))
	{
		// Recurse content for ReplaceOnSaveTags
		if(strpos($content, '<') !== false)
		{
			$temp = $content;
			ReplaceOnSave_ArticleSave($article, $user, $temp, $summary, $minoredit, $watchthis, $sectionanchor);
			if($temp != $content)
			{
				$fulltag = str_replace($content, $temp, $fulltag);
				$content = $temp;
			}
		}
		
		// Parse up the full tag to separate the parameters and content for encryption
		// Encrypt the data 
		// Example1: <element p1="1" p2="2">content</element>
		// data = "  p1="1" p2="2">content"
		// Example2: <element p1="1" p2="2"/>
		// data = " p1="1" p2="2"/>"
		// Example3: <element>content</element>
		// data = ">content"
		// Example4: <element/>
		// data = "/>"
		
		// If attributes were specified (Example1 & 2)
		if(count($params) > 0)
		{
			// Start with first char after <element
			$start = strlen($tag) + 1;
			// If second to last char is / Example 2)
			if($fulltag[strlen($fulltag)-2] == '/')
				// Set data to everything remaining in the string (includes /> )
				$data = substr($fulltag, $start);
			else 
			{
				// Example1
				// Set end to the last < encountered (first character of closing tag)
				$end = strrpos($fulltag, '<');
				
				$data = substr($fulltag, $start, $end - $start);
			}
		}
		else
		{
			// No parameters (Examples3 & 4)
			// If there is content
			if($content != '')
			{
				// Example3
				// Set start to the first closing bracket (of the opening element tag)
				$start = strpos($fulltag, '>');
				// Set end to the last < encountered (first character of closing tag)
				$end = strrpos($fulltag, '<');
				
				$data = substr($fulltag, $start, $end - $start);
			}
			// Example4
			
			else $data = '/>';
		}

		$etext = Secure_Encrypt($data, $params);
		
		// Split up encrypted text for readability in history page
		$etext = chunk_split($etext, 40, "\n");
		
		// If encryption fails then just put full tag in unencrypted
		if($etext !== false)
			// Replace with encrypted parameters and contents
			return "<$tag>\n$etext</$tag>";
	}
	return false;
}

function Secure_ReplaceNoAccessOnSave($tag, $content, $params, $fulltag, $article, $user, $text, $summary, $minoredit, $watchthis, $sectionanchor)
{
	global $gPrevArticleCached, $gPrevMatches, $gSecureParseTags;
	
	// Cache the previous articles secure tag matches
	if(!$gPrevArticleCached)
	{
		$gPrevArticleCached = true;
		
		Parser::extractTagsAndParams(
				$gSecureParseTags
//			   array(SECURE_TAG, NOWIKI_TAG, PRE_TAG),
			   ,$article->getContent()
			   ,$temp );	

		// Loop through previous tag matches
		foreach($temp as $k => $v)
		{
			$_tag = $v[0];
			$_fulltag = $v[3];
			
//			dout("Secure_ReplaceNoAccessOnSave: $_fulltag\n");
			
	//		$_content = $v[1];
	//		$_params = $v[2];

			// Matches also contains comments, so only add secure blocks to match list
			if(Secure_IsSecureTag($_tag))
//			if($v[0] == SECURE_TAG)
				$gPrevMatches[] = $_fulltag;
		}

	}
	
	// Figure out the number of this noaccess match
	$start = strpos($fulltag, ' ') + 1;
	$end = strpos($fulltag, '/');
	$which = substr($fulltag, $start, $end - $start) - 1;
	
	if(isset($gPrevMatches[$which]))
		return $gPrevMatches[$which];
	return false;
}

function Secure_IsEncrypted($t)
{
	global $gSecureHook;
	
	// If length of t is less than size of sig32 then there is no way to decrypt it
	if(strlen($t) < 32)
		return false;
		
	// Get the first 32 characters as the signature
	$sig = substr($t, 0, 32);

	// Return true if there is a decrypt hook set for the sig32
	return isset($gSecureHook['decrypt'][$sig]);
}

function Secure_Encrypt($t, $params)
{
	global $gSecureHook;
	
	// if the method parameter is set
	if(isset($params[METHOD_ATTR]))
	{
		// Get the value of the method parameter
		$method = $params[METHOD_ATTR];
		// If there is an encrypt hook for the method specified
		if(isset($gSecureHook['encrypt'][$method]))
		{
			// Return the sig32 with the encrypted characters appended to it
			return $gSecureHook['sig32'][$method] 
				. call_user_func($gSecureHook['encrypt'][$method], $t, $params);
		}
		// Method specified not found, use default method
	}
	// No method specified, use first encryption method found
	foreach($gSecureHook['encrypt'] as $k => $v)
		// Return the sig32 with the encrypted characters appended to it
		return $gSecureHook['sig32'][$k] . call_user_func($v, $t,$params);
	// No encryption hooked
	return false;
}

function Secure_Decrypt($t)
{
	global $gSecureHook;
	
	// If length of t is less than size of sig32 then there is no way to decrypt it
	if(strlen($t) < 32)
		return false;
		
	// Get the first 32 characters as the signature
	$sig = substr($t, 0, 32);
	
	// If there is a decrypt hook set for the sig 32
	if(isset($gSecureHook['decrypt'][$sig]))
		// Return the result of the decryption (sig32 chopped first)
		return call_user_func($gSecureHook['decrypt'][$sig], substr($t, 32));
	// No decryption method for that signature
	return false;
}

//function Secure_GetUserText($params)
function Secure_SecureTagHook($isOwner, $content, $params, &$parser)
{
	global $wgUser;
	$user = $wgUser->getName();
	$user = strtr($user, " ", "_");
	
	if($isOwner)
		return $content;

	if($wgUser->isAnon())
		return $params[ANYONE_ATTR];
		
	// Translate spaces into _ for values
	foreach($params as $v)
		$v = strtr($v, " ", "_"); 
	
	// Look if this specific user has text applied
	if(isset($params[$user]))
		return $params[$user];

	// Look for security groups
	foreach($params as $k => $v)
	{
		// If the first 5 characters of the attribute name is group it is a group name
		if(strncasecmp(GROUP_ATTR, $k, 5)==0)
		{
			// Split the value into a userlist
			$userlist = explode(',', $v);
			// If the current user is not in this list then just skip this one
			if(!in_array($user, $userlist))
				continue;
			// User is in list so return the _text parameter
			return $params[$k . GROUPTEXT_ATTR];
		}
	}
		
//	if(!isset($params[OWNER_ATTR]) && !isset($params[READ_ATTR]))
	if(!isset($params[READ_ATTR]))
		return $params[ANYONE_ATTR];
	else
	{
		// Parse the user list
//		$ownerlist = explode(',', $params[OWNER_ATTR]);
//		$readlist = explode(',', $params[READ_ATTR]);
		$userlist = explode(',', $params[READ_ATTR]);
//		$userlist = array_merge($ownerlist, $readlist);
	
		// If no user list is found OR if the user is in the user list
	
		if(in_array($user, $userlist) || in_array('*', $userlist) )
			return $content;
	}	
	// User is not in the list, return only the anyone parameter
	return $params[ANYONE_ATTR];
}

/*
<secure2 owner="Illumanus">
<t0>blahblah</t0>
<t1 users="User1,User2,User3"> blah </t1>
<t2 users="User1,User2,User3"> blah2 </t2>
<t3 users="User1,User2,User3"> blah2 </t3>
</secure2>

<secure2 owner="Illumanus">
<t0><tile tile=Tile-Back/></t0>
<t1 read="User1,User2,User3">
 <tile tile=Tile-Abyz-Fria/>
</t2>
<t3 read="User3,User4,User5">
 <tile tile=Tile-Abyz-Fria>
 <cruiser where=0/>
 </tile>
</t3>
</secure2>
*/

function Secure_Secure2TagHook($isOwner, $content, $params, &$parser)
{
	global $wgUser;
	$user = $wgUser->getName();
	$user = strtr($user, " ", "_");
	$user_n = -1;
	
	$ptext = Parser::extractTagsAndParams(
//					   array(SECURE_TAG, NOWIKI_TAG, PRE_TAG),
						array('t0', 't1', 't2', 't3', 't4', 't5', 't6', 'anyone')
						,$content
						,$matches );	

	foreach($matches as $k => $i)
	{
		$_tag = $i[0];
		$_content = $i[1];
		$_params = $i[2];
		$_fulltag = $i[3];
		
		switch($_tag)
		{
			case 'anyone' :
				$_tag = 't0';
			default :
				if(substr($_tag,0,1) == 't' && strlen($_tag) == 2)
				{
					$n = substr($_tag,1,1);
					if($user_n < $n)
					{
						$readlist = explode(',', strtr($_params[READ_ATTR], " ", "_"));
						if($isOwner || $_tag == 't0' || (isset($_params[READ_ATTR]) && in_array($user, $readlist)))
						{
							$retv = $_content;
							$user_n = $n;
						}
					}
				}
			
		}
	}
	return trim($retv);
}


?>