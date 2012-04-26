%%%----------------------------------------------------------------------
%%% File    : mod_websocket.erl
%%% Author  : Nathan Zorn <nathan.zorn@gmail.com>
%%% Purpose : XMPP over websockets
%%%
%%% Part of this has been taken from misultin (https://github.com/ostinelli/misultin.git),
%%% license BSD. If this is possible comparing with the GPL license of this module needs to be cleared.
%%% TODO: Ask ostinelli about that.
%%%----------------------------------------------------------------------

-module(mod_websocket).
-author('nathan.zorn@gmail.com').

-define(MOD_WEBSOCKET_VERSION, "0.1").
-define(TEST, ok).
-define(PROCNAME_MHB, ejabberd_mod_websocket).

-behaviour(gen_mod).

-export([
         start/2,
         stop/1,
         process/2
        ]).

-include("ejabberd.hrl").
-include("jlib.hrl").
-include("ejabberd_websocket.hrl").
-record(wsdatastate, {legacy=true,
                      ft=undefined,
                      flen,
                      packet= <<>>,
                      buffer= <<>>,
                      partial= <<>>
                     }).

% records
-record(state, {
	buffer	= <<>>,
	mask_key  = <<0,0,0,0>>,
	fragments = [] %% if we are in the midst of receving a fragmented message, fragments are contained here in reverse order
}).

-record(frame, {fin,
				rsv1,
				rsv2,
				rsv3,
				opcode,
				maskbit,
				length,
				maskkey,
				data}).

% macros
-define(OP_CONT, 0).
-define(OP_TEXT, 1).
-define(OP_BIN, 2).
-define(OP_CLOSE, 8).
-define(OP_PING, 9).
-define(OP_PONG, 10).

-define(IS_CONTROL_OPCODE(X), ((X band 8)=:=8) ).

%% If we don't find a websocket protocol frame in this many bytes, connection aborts
-define(MAX_UNPARSED_BUFFER_SIZE, 1024 * 100).
%%%----------------------------------------------------------------------
%%% API
%%%----------------------------------------------------------------------
process(Path, Req) ->
    ?DEBUG("Request data:~p:", [Path, Req]),
    %% Validate Origin
    case validate_origin(Req#wsrequest.headers) of
        true ->
            Data = case Req#wsrequest.data of
                       [] -> <<>>;
                       X when is_list(X) ->
                           list_to_binary(X);
                       socket_closed ->
                           ?DEBUG("socket closed", []),
                           build_stream_end();
                       Y ->
                           Y
                   end,
            ?DEBUG("Origin is valid.",[]),
            DState = #wsdatastate {legacy=true,
                                   buffer=Data,
                                   ft=undefined,
                                   partial= <<>> },
            case Data of
                undefined ->
                    {<<>>, <<>>};
                _ ->
                    case take_frame(Data) of
                		{error, max_size_reached} ->
                			?DEBUG("reached max unparsed buffer size, aborting connection", []),
                			{error, max_size_reached};
                		{undefined, Rest} ->
                			?DEBUG("no frame to take, add to buffer: ~p", [Rest]),
                			%% no full frame to be had yet
                			DState#wsdatastate{buffer = Rest};
                		{Frame=#frame{}, Rest} ->
                			?DEBUG("parsed frame ~p, remaining buffer is: ~p", [Frame,Rest]),
                			%% sanity check, in case client is broken
                			case sanity_check(Frame) of
                				true ->
                					?DEBUG("sanity checks successfully performed",[]),
                					ejabberd_xmpp_websocket:process_request(
                					    Req#wsrequest.wsockmod,
                                        Req#wsrequest.wsocket,
                                        Req#wsrequest.fsmref,
                                        Frame#frame.data,
                                        Req#wsrequest.ip);
                				false -> % protocol error
                					?DEBUG("sanity checks errors encountered, closing websocket",[]),
                					{error, sanity_check}
                			end;
                		_ ->
                		    ?DEBUG("wtf?", [])
                	end
            end;
        _ ->
            ?DEBUG("Invalid Origin in Request: ~p~n",[Req]),
            false
    end.

%%%----------------------------------------------------------------------
%%% BEHAVIOUR CALLBACKS
%%%----------------------------------------------------------------------
start(Host, _Opts) ->
    Proc = gen_mod:get_module_proc(Host, ?PROCNAME_MHB),
    ChildSpec =
        {Proc,
         {ejabberd_tmp_sup, start_link,
          [Proc, ejabberd_xmpp_websocket]},
         permanent,
         infinity,
         supervisor,
         [ejabberd_tmp_sup]},
    supervisor:start_child(ejabberd_sup, ChildSpec).

stop(Host) ->
    ?DEBUG("stop mod_websocket", []),
    Proc = gen_mod:get_module_proc(Host, ?PROCNAME_MHB),
    supervisor:terminate_child(ejabberd_sup, Proc),
    supervisor:delete_child(ejabberd_sup, Proc).
%% Origin validator - Ejabberd configuration should contain a fun
%% validating the origin for this request handler? Default is to
%% always validate.
validate_origin([]) ->
    true;
validate_origin(Headers) ->
    is_tuple(lists:keyfind("Origin", 1, Headers)).
    
% ---------------------------- \/ frame parsing ------------------------------------------------------------

% format sanity checks
-spec sanity_check(#frame{}) -> true | false.
sanity_check(Frame) ->
	Checks = [
		{1, Frame#frame.maskbit},
		{0, Frame#frame.rsv1},
		{0, Frame#frame.rsv2},
		{0, Frame#frame.rsv3}
	],
	lists:foldl(fun({A,B}, Acc) -> Acc andalso (A =:= B) end, true, Checks).

% parse received data and get the frames
-spec take_frame(Data::binary()) -> {#frame{} | undefined, Rest::binary()} | {error, max_size_reached}.
% normal length
take_frame(<<Fin:1, 
			 Rsv1:1, %% Rsv1 = 0
			 Rsv2:1, %% Rsv2 = 0
			 Rsv3:1, %% Rsv3 = 0
			 Opcode:4,
			 MaskBit:1, %% must be 1
			 PayloadLen:7,
			 MaskKey:4/binary,
			 PayloadData:PayloadLen/binary-unit:8,
			 Rest/binary>>) when PayloadLen < 126 ->
	%% Don't auto-unmask control frames
    ?DEBUG("tk1", []),
	Data = case ?IS_CONTROL_OPCODE(Opcode) of
		true  -> PayloadData;
		false -> unmask(MaskKey,PayloadData)
	end,
	{#frame{fin=Fin, 
			rsv1=Rsv1,
			rsv2=Rsv2,
			rsv3=Rsv3,
			opcode=Opcode,
			maskbit=MaskBit,
			length=PayloadLen,
			maskkey=MaskKey,
			data = Data}, Rest};
% extended payload (126)
take_frame(<<Fin:1, 
			 Rsv1:1, %% Rsv1 = 0
			 Rsv2:1, %% Rsv2 = 0
			 Rsv3:1, %% Rsv3 = 0
			 Opcode:4,
			 MaskBit:1, %% must be 1
			 126:7,
			 PayloadLen:16,
			 MaskKey:4/binary,
			 PayloadData:PayloadLen/binary-unit:8,
			 Rest/binary>>) ->
    ?DEBUG("tk2", []),
	{#frame{fin=Fin, 
			rsv1=Rsv1,
			rsv2=Rsv2,
			rsv3=Rsv3,
			opcode=Opcode,
			maskbit=MaskBit,
			length=PayloadLen,
			maskkey=MaskKey,
			data=unmask(MaskKey,PayloadData)},	Rest};
% extended payload (127)
take_frame(<<Fin:1, 
			 Rsv1:1, %% Rsv1 = 0
			 Rsv2:1, %% Rsv2 = 0
			 Rsv3:1, %% Rsv3 = 0
			 Opcode:4,
			 MaskBit:1, %% must be 1
			 127:7, %% "If 127, the following 8 bytes interpreted as a 64-bit unsigned integer (the most significant bit MUST be 0)" 
			 0:1,	%% MSB of 0
			 PayloadLen:63,
			 MaskKey:4/binary,
			 PayloadData:PayloadLen/binary-unit:8,
			 Rest/binary>>) ->
    ?DEBUG("tk3", []),
	{#frame{fin=Fin, 
			rsv1=Rsv1,
			rsv2=Rsv2,
			rsv3=Rsv3,
			opcode=Opcode,
			maskbit=MaskBit,
			length=PayloadLen,
			maskkey=MaskKey,
			data=unmask(MaskKey, PayloadData)},	 Rest};
			
% incomplete frame
take_frame(Data) when is_binary(Data), size(Data) < ?MAX_UNPARSED_BUFFER_SIZE ->
    ?DEBUG("tk4", []),
	{undefined, Data};
% Try to prevent denial-of-service from clients that send an infinite stream of
% incompatible data
take_frame(Data) when is_binary(Data), size(Data) >= ?MAX_UNPARSED_BUFFER_SIZE ->
    ?DEBUG("tk5", []),
	{error, max_size_reached}.    


% unmask
-spec unmask(Key::binary(), Data::binary()) -> binary(). 
unmask(Key, <<_:512,_Rest/binary>> = Data) ->
	K = binary:copy(Key, 512 div 32),
	<<LongKey:512>> = K,
	<<ShortKey:32>> = Key,
	unmask(ShortKey, LongKey, Data, <<>>);
unmask(Key, Data) ->
	<<ShortKey:32>> = Key,
	unmask(ShortKey,none, Data, <<>>).
unmask(Key, LongKey, Data, Accu) ->
	case Data of
		<<A:512, Rest/binary>> ->
			C = A bxor LongKey,
			unmask(Key, LongKey, Rest, <<Accu/binary, C:512>>);
		<<A:32,Rest/binary>> ->
			C = A bxor Key,
			unmask(Key, LongKey, Rest, <<Accu/binary, C:32>>);
		<<A:24>> ->
			<<B:24, _:8>> = <<Key:32>>,
			C = A bxor B,
			<<Accu/binary, C:24>>;
		<<A:16>> ->
			<<B:16, _:16>> = <<Key:32>>,
			C = A bxor B,
			<<Accu/binary, C:16>>;
		<<A:8>> ->
			<<B:8, _:24>> = <<Key:32>>,
			C = A bxor B,
			<<Accu/binary, C:8>>;
		<<>> ->
			Accu
	end.
    
%% For now only build a legacy stream end packet
build_stream_end() ->
    list_to_binary([0,<<"</stream:stream>">>,255]).
%%
%% Tests
%%
-include_lib("eunit/include/eunit.hrl").
-ifdef(TEST).

websocket_process_data_test() ->
    %% Test frame arrival.
    Packets = [<<0,"<tagname>",255>>,
               <<0,"<startag> ">>,
               <<"cdata in startag ">>,
               <<"more cdata </startag>",255>>,
               <<0,"something about tests",255>>,
               <<0,"fragment">>],

    Buffer = <<>>,
    Packet = lists:nth(1,Packets),
    FinalState = take_frame(<<Buffer/binary,Packet/binary>>),
    {<<"<tagname>">>,<<>>} = FinalState,
    Packet0 = lists:nth(2,Packets),
    {_,Buffer0} = FinalState,
    FinalState0 = take_frame(<<Buffer0/binary,Packet0/binary>>),
    {<<>>,<<"<startag> ">>} = FinalState0,
    Packet1 = lists:nth(3,Packets),
    {_,Buffer1} = FinalState0,
    FinalState1 = take_frame(<<Buffer1/binary,Packet1/binary>>),
    {<<>>,<<"<startag> cdata in startag ">>} = FinalState1,
    Packet2 = lists:nth(4,Packets),
    {_, Buffer2} = FinalState1,
    FinalState2 = take_frame(<<Buffer2/binary,Packet2/binary>>),
    {<<"<startag> cdata in startag more cdata </startag>">>,<<>>} = FinalState2,
    Packet3 = lists:nth(5,Packets),
    {_,Buffer3} = FinalState2,
    FinalState3 = take_frame(<<Buffer3/binary,Packet3/binary>>),
    {<<"something about tests">>,<<>>} = FinalState3,
    ok.

-endif.
