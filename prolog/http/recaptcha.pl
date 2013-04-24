/*  Part of SWI-Prolog

    Author:        Jan Wielemaker
    E-mail:        J.Wielemaker@cs.vu.nl
    WWW:           http://www.swi-prolog.org
    Copyright (C): 2013, VU University Amsterdam

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    As a special exception, if you link this library with other files,
    compiled with a Free Software compiler, to produce an executable, this
    library does not by itself cause the resulting executable to be covered
    by the GNU General Public License. This exception does not however
    invalidate any other reasons why the executable file might be covered by
    the GNU General Public License.
*/

:- module(recaptcha,
	  [ recaptcha//1,		% +Options
	    recaptcha_parameters/1,	% -HTTP parameter list
	    recaptcha_verify/2		% +Request, +HTTPParamList
	  ]).
:- use_module(library(http/html_head)).
:- use_module(library(http/html_write)).
:- use_module(library(http/http_open)).
:- use_module(library(error)).
:- use_module(library(option)).

:- html_resource(
       recaptcha,
       [ virtual(true),
	 requires([ 'http://www.google.com/recaptcha/api/js/recaptcha_ajax.js'
		  ])
       ]).

/** <module> Add reCAPTCHA functionality to a form

This module is a plugin for the   SWI-Prolog  HTTP/HTML framework to add
reCAPTCHA functionality to a form.  It works as follows:

  1. Load library(http/recaptcha) and define the reCAPTCHA keys
     as described in key/2.

  2. Create a form, typically using method('POST') and include,
     in addition to the data you request from the human user,
     the reCAPTCHA widget using e.g.,

         \recaptcha([theme(red)])

  3. In the handler of the form, you must ask for the recaptcha
     parameters and pass them to recaptcha_verify/2.  You can do
     that as follows:

         process_recaptcha_form(Request) :-
		recaptcha_parameters(RecapthaParams),
		http_parameters(Recaptha,
				[ name(Name, []),
				  age(Age, []),
				  ...
				| RecapthaParams
				]),
		(   recaptcha_verify(Request, RecapthaParams)
		->  <process normal user fields>
		;   <you are not human>
		).

@see examples/demo.pl contains a fully functional demo.
*/


:- multifile
	key/2.

%%	recaptcha(+Options)// is det.
%
%	Display the reCAPTCHA widget.  Defined options are:
%
%	  * theme(+Theme)
%	  Set the theme.  The default theme is =clean=.
%
%	@see	https://developers.google.com/recaptcha/docs/customization
%		describes the available themes

recaptcha(Options) -->
	{ (   key(public, PublicKey)
	  ->  true
	  ;   existence_error(recaptcha_key, public)
	  ),
	  option(theme(Theme), Options, clean)
	},
	html_requires(recaptcha),
	html(div(id(recaptcha), [])),
	create_captcha(recaptcha, PublicKey, Theme).


create_captcha(Id, PublicKey, Theme) -->
	html(script(type('text/javascript'),
		    \[ 'Recaptcha.create("',PublicKey,'",\n',
		       '                 "',Id,'",\n',
		       '                 {\n',
		       '		     theme:"',Theme,'"\n',
		       '                 });\n'
		     ])).


%%	recaptcha_parameters(-List) is det.
%
%	List is a list  of  parameters   for  http_parameters/3  that is
%	needed for recaptcha_verify/2.

recaptcha_parameters(
    [ recaptcha_challenge_field(_Challenge, []),
      recaptcha_response_field(_Response, [])
    ]).


%%	recaptcha_verify(+Request, +Parameters) is semidet.
%
%	Is true if the user solved the   captcha correctly. Fails if the
%	user did not solve the captcha correctly  but there was no error
%	processing the request.
%
%	@error	recaptcha_error(Error) is raised if there was an error
%		processing the captcha.
%	@see	https://developers.google.com/recaptcha/docs/verify
%		lists the errors.

recaptcha_verify(Request, Parameters) :-
	memberchk(recaptcha_challenge_field(Challenge, _), Parameters),
	memberchk(recaptcha_response_field(Response, _), Parameters),
	recaptcha_verify(Request, Challenge, Response).

recaptcha_verify(Request, Challenge, Response) :-
	remote_IP(Request, Peer),
	(   key(private, PrivateKey)
	->  true
	;   existence_error(recaptcha_key, private)
	),
	setup_call_cleanup(
	    http_open('http://www.google.com/recaptcha/api/verify',
		      In,
		      [ post(form([ privatekey(PrivateKey),
				    remoteip(Peer),
				    challenge(Challenge),
				    response(Response)
				  ]))
		      ]),
	    read_stream_to_lines(In, Lines),
	    close(In)),
	maplist(atom_codes, Atoms, Lines),
	(   Atoms = [true|_]
	->  true
	;   Atoms = [false, 'incorrect-captcha-sol'|_]
	->  fail
	;   Atoms = [false, Error, _],
	    throw(error(recaptcha_error(Error), _))
	).


read_stream_to_lines(In, Lines) :-
	read_line_to_codes(In, Line0),
	read_stream_to_lines(Line0, In, Lines).

read_stream_to_lines(end_of_file, _, []) :- !.
read_stream_to_lines(Line, In, [Line|More]) :-
	read_line_to_codes(In, Line1),
	read_stream_to_lines(Line1, In, More).


remote_IP(Request, IP) :-
        memberchk(x_forwarded_for(IP0), Request), !,
	atomic_list_concat(Parts, ', ', IP0),
	last(Parts, IP).
remote_IP(Request, IP) :-
        memberchk(peer(Peer), Request), !,
        peer_to_ip(Peer, IP).
remote_IP(_, -).


peer_to_ip(ip(A,B,C,D), IP) :-
        atomic_list_concat([A,B,C,D], '.', IP).

%%	key(+Which, -Key) is det.
%
%	This hook must unify Key to the reCAPTCHA public key if Which us
%	=public= and to the reCAPTCHA private key if Which is =private=.
%
%	We leave the key handling to a hook to accomodate different ways
%	for storing and transferring the   keys. A simple implementation
%	is:
%
%	  ==
%	  :- use_module(library(http/recaptcha)).
%
%	  :- multifile recaptcha:key/2.
%
%	  recaptcha:key(public,  'Public key goes here').
%	  recaptcha:key(private, 'Private key goes here').
%	  ==


