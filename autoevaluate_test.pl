#! /usr/bin/perl 
# You may need to modify this ^^ based on your platform and location of the perl binary

use File::Compare;

my $proxyhost = '182.75.45.22';
my $proxyport = '13128';
my $proxyuser = 'csf303';
my $proxypass = 'csf303';
my $target = "www.go.com";
my $htmltarget = 'index.html';
my $logotarget = 'logo.jpeg';
my $filename = 'http_proxy_download.c';
my $binname = 'http_proxy_download.out';
my $standardfilename = "std_html.html";
my $standardlogo = "std_logo.jpeg";
my $std_html = "std_html.html";

my $file;
my $email, $name;
open($file, "<", $filename) or print $!." "."$filename";

@lines = <$file>;
$lines[0] =~ m/\/\*\s+(.*?)\s+(.*)\s+\*\//;
$email = $1;
$name = $2;

print "Name: |$name|\n";
print "Email: |$email|\n";

my $compileout = `gcc "$filename" -o $binname 2>compile.err`;
my $compileerr = `cat compile.err`;
print "Compile output:\n\n$compileout\n\n";
print "Compile error:\n\n$compileerr\n\n";

if (-e $htmltarget)
{
	`rm $htmltarget`;
}
if (-e $logotarget)
{
	 `rm $logotarget`;
}
	
if (-e "$binname")
{
	my $runout = `./$binname $target $proxyhost $proxyport $proxyuser $proxypass $htmltarget $logotarget 2> run.err`;
	my $runerr = `cat run.err`;
	print "Run output:\n\n$runout\n\n";
	print "Run error:\n\n$runerr\n\n";
}
else
{
	print "Run error: Binary has not been generated\n";
}
if (-e "$htmltarget")
{
		if (compare($htmltarget, $std_html) == 0)
		{
			print "Base HTML matches\n";
		}
		else
		{
			print "Base HTML does not match\n";
		}
		
		if (compare($logotarget, $std_logo) == 0)
		{
			print "Logo matches\n";
		}
		else
		{
			print "Logo does not match\n";
		}
		
}
close($file);

