%%%----------------------------------------------------------------------
%%% File    : ejabberd_xmpp_websocket.erl
%%% Author  : Nathan Zorn (nathan.zorn@gmail.com)
%%% Purpose : Implements XMPP over WebSockets
%%%----------------------------------------------------------------------
-module(ejabberd_xmpp_websocket).

-behaviour(gen_fsm).

-export([start_link/3,
	 init/1,
	 handle_event/3,
	 handle_sync_event/4,
	 code_change/4,
	 handle_info/3,
	 terminate/3,
	 send/2,
	 send_xml/2,
	 sockname/1,
	 peername/1,
	 setopts/2,
	 controlling_process/2,
	 become_controller/2,
	 custom_receiver/1,
	 reset_stream/1,
	 change_shaper/2,
	 monitor/1,
	 close/1,
	 start/4,
	 process_request/5]).


-define(LAGER,1).

-include("ejabberd.hrl").
-include("logger.hrl").
-include("xml.hrl").

%% Module constants
-define(NULL_PEER, {{0, 0, 0, 0}, 0}).
-define(MAX_INACTIVITY, 30000000). % msecs to wait before terminating
                                % idle sessions
-define(MAX_PAUSE, 120). % may num of sec a client is allowed to pause
                         % the session
-define(NS_CLIENT, "jabber:client").
-define(NS_STREAM, "http://etherx.jabber.org/streams").
-define(TEST, 1).


% macros
-define(OP_CONT, 0).
-define(OP_TEXT, 1).
-define(OP_BIN, 2).
-define(OP_CLOSE, 8).
-define(OP_PING, 9).
-define(OP_PONG, 10).

%%  Erlang Records for state
-record(wsr, {socket, sockmod, key, out}).

-record(state, {id,
		key,
		socket,
		output = "",
		input = queue:new(),
		waiting_input = false,
		shaper_state,
		shaper_timer,
		websocket_sockmod,
		websocket_s,
		websocket_receiver,
		wait_timer,
		timer,
		pause=0,
		max_inactivity,
		max_pause,
		ip = ?NULL_PEER
}).

start(Host, Sid, Key, IP) ->
    ?DEBUG("Starting ejabberd_xmpp_websocket", []),
    ?DEBUG("Host: ~p; Sid: ~p; Key: ~p, IP: ~p", [Host, Sid, Key, IP]),
    Proc = gen_mod:get_module_proc(Host, ejabberd_mod_websocket),
    case catch supervisor:start_child(Proc, [Sid, Key, IP]) of
        {ok, Pid} -> {ok, Pid};
        Reason ->
            ?ERROR_MSG("~p~n",[Reason]),
            {error, "Cannot start XMPP, Websocket session"}
    end.

start_link(Sid, Key, IP) ->
	?DEBUG("Starting ejabberd_mod_websocket", []),
    gen_fsm:start_link(?MODULE, [Sid, Key, IP], []).

send({xmpp_websocket, FsmRef, _IP}, Packet) ->
    ?DEBUG("xmpp_websocket send", []),
    gen_fsm:sync_send_all_state_event(FsmRef, {send, Packet}).

send_xml({xmpp_websocket, FsmRef, _IP}, Packet) ->
    ?DEBUG("xmpp_websocket send_xml", []),
    gen_fsm:sync_send_all_state_event(FsmRef, {send_xml, Packet}).

setopts({xmpp_websocket, FsmRef, _IP}, Opts) ->
    ?DEBUG("xmpp_websocket setopts", []),
    case lists:member({active, once}, Opts) of
	    true ->
	        gen_fsm:send_all_state_event(FsmRef, {activate, self()});
	    _ ->
	        ok
    end.

controlling_process(_Socket, _Pid) ->
    ok.

custom_receiver({xmpp_websocket, FsmRef, _IP}) ->
    {receiver, ?MODULE, FsmRef}.

become_controller(FsmRef, C2SPid) ->
    gen_fsm:send_all_state_event(FsmRef, {become_controller, C2SPid}).

reset_stream({xmpp_websocket, _FsmRef, _IP}) ->
    ok.

change_shaper({xmpp_websocket, FsmRef, _IP}, Shaper) ->
    gen_fsm:send_all_state_event(FsmRef, {change_shaper, Shaper}).

monitor({xmpp_websocket, FsmRef, _IP}) ->
    erlang:monitor(process, FsmRef).

close({xmpp_websocket, FsmRef, _IP}) ->
    ?DEBUG("close, xmpp:websocket", []),
    catch gen_fsm:sync_send_all_state_event(FsmRef, {stop, close}).

sockname(_Socket) ->
    {ok, ?NULL_PEER}.

peername({xmpp_websocket, _FsmRef, IP}) ->
    {ok, IP}.

%% entry point for websocket data
process_request(WSockMod, WSock, FsmRef, Data, IP) ->
    ?DEBUG("FsmRef is ~p", [FsmRef]),
    Opts1 = ejabberd_c2s_config:get_c2s_limits(),
    Opts = [{xml_socket, true} | Opts1],
    MaxStanzaSize = case lists:keysearch(max_stanza_size, 1, Opts) of
	    {value, {_, Size}} -> Size;
	    _ -> infinity
	end,
    PayloadSize = iolist_size(Data),
    ?DEBUG("MaxStanzaSize: ~p~n PayloadSize: ~p", [MaxStanzaSize, PayloadSize]),
    case validate_request(Data, PayloadSize, MaxStanzaSize) of
        {ok, ParsedPayload} ->
            ?DEBUG("Parsed Payload: ~p", [ParsedPayload]),
            SStart = stream_start(ParsedPayload),
            ?DEBUG("*******************~p", [SStart]),
            case SStart of
                {Host, Sid, Key} when (FsmRef =:= false) or
                                      (FsmRef =:= undefined) ->
                    case start(Host, Sid, Key, IP) of
                        {ok, Pid} ->
                            ?DEBUG("Session Pid:~p~n",[Pid]),
                            gen_fsm:sync_send_all_state_event(
                              Pid,
                              #wsr{sockmod=WSockMod,
                                   socket=WSock,
                                   out=[{xmlstreamstart, "stream:stream", ParsedPayload#xmlel.attrs}]}),
                            ?DEBUG("session started", []),
                            {<<"session started">>, <<>>, Pid};
                        S ->
                            ?ERROR_MSG("Error starting session:~p~n", [S])
                    end;
                {_Host, _Sid, _Key} when (FsmRef =/= false) or
                                         (FsmRef =/= undefined) ->
                    ?DEBUG("Stream restart after c2s started. ~p~n",
                           [FsmRef]),
                    send_data(FsmRef, #wsr{sockmod=WSockMod,
                                           socket=WSock,
                                           out=[{xmlelement, "stream:stream", ParsedPayload#xmlel.attrs}]}),
                    {Data, <<>>, FsmRef};
                false ->
                    ?DEBUG("stream start: false", []),
                    send_data(FsmRef, #wsr{sockmod=WSockMod,
                                           socket=WSock,
                                           out=[ParsedPayload]}),
                    {Data, <<>>, FsmRef};
                _ ->
                    ?ERROR_MSG("Stream Start with no FSM reference: ~p~n",
                               [FsmRef]),
                    {Data, <<>>, FsmRef}
            end;
        _ ->
            ?DEBUG("Bad Request: ~p~n", [Data]),
            {<<"bad request">>, <<>>, FsmRef}
    end.

%%%----------------------------------------------------------------------
%%% Callback functions from gen_fsm
%%%----------------------------------------------------------------------

%%----------------------------------------------------------------------
%% Func: init/1
%% Returns: {ok, StateName, StateData}          |
%%          {ok, StateName, StateData, Timeout} |
%%          ignore                              |
%%          {stop, StopReason}
%%----------------------------------------------------------------------
init([Sid, Key, IP]) ->
    ?DEBUG("started: ~p", [{Sid, Key, IP}]),
    Opts1 = ejabberd_c2s_config:get_c2s_limits(),
    Opts = [{xml_socket, true} | Opts1],

    Shaper = none,
    ShaperState = shaper:new(Shaper),
    Socket = {xmpp_websocket, self(), IP},
    ejabberd_socket:start(ejabberd_c2s, ?MODULE, Socket, Opts),
    Timer = erlang:start_timer(?MAX_INACTIVITY, self(), []),
    {ok, loop, #state{id = Sid,
		      key = Key,
		      socket = Socket,
		      shaper_state = ShaperState,
		      max_inactivity = ?MAX_INACTIVITY,
		      max_pause = ?MAX_PAUSE,
		      timer = Timer}}.

%%----------------------------------------------------------------------
%% Func: handle_event/3
%% Returns: {next_state, NextStateName, NextStateData}          |
%%          {next_state, NextStateName, NextStateData, Timeout} |
%%          {stop, Reason, NewStateData}
%%----------------------------------------------------------------------
handle_event({become_controller, C2SPid}, StateName, StateData) ->
    ?DEBUG("C2SPid:~p~nStateName:~p~nData:~p~n",
           [C2SPid, StateName, StateData#state.input]),
    case StateData#state.input of
	    cancel ->
	        ?DEBUG("CANCEL", []),
	        {next_state, StateName, StateData#state{
	            waiting_input = C2SPid}};
	    Input ->
	        lists:foreach(
	            fun([]) ->
                      %% skip
                      ?DEBUG("Empty input queue.",[]);
                 (Event) ->
                     ?DEBUG("send event: ~p", [Event]),
                      C2SPid ! Event
                end, queue:to_list(Input)),
	    {next_state, StateName, StateData#state{
				      input = queue:new(),
				      waiting_input = C2SPid}}
    end;

handle_event({change_shaper, Shaper}, StateName, StateData) ->
    ?DEBUG("change shaper", []),
    NewShaperState = shaper:new(Shaper),
    {next_state, StateName, StateData#state{shaper_state = NewShaperState}};
handle_event(_Event, StateName, StateData) ->
    ?DEBUG("handle event next state", []),
    {next_state, StateName, StateData}.

%%----------------------------------------------------------------------
%% Func: handle_sync_event/4
%% Returns: {next_state, NextStateName, NextStateData}            |
%%          {next_state, NextStateName, NextStateData, Timeout}   |
%%          {reply, Reply, NextStateName, NextStateData}          |
%%          {reply, Reply, NextStateName, NextStateData, Timeout} |
%%          {stop, Reason, NewStateData}                          |
%%          {stop, Reason, Reply, NewStateData}
%%----------------------------------------------------------------------
handle_sync_event({send_xml, Packet}, _From, StateName,
		  #state{websocket_s = undefined} = StateData) ->
	?DEBUG("send xml", []),
    Output = [Packet | StateData#state.output],
    Reply = ok,
    {reply, Reply, StateName, StateData#state{output = Output}};
handle_sync_event({send_xml, Packet}, _From, StateName, StateData) ->
    Output = [Packet | StateData#state.output],
    ?DEBUG("Data from C2S(timer):~p:~p~n",[Output,StateData]),
    cancel_timer(StateData#state.timer),
    Timer = set_inactivity_timer(StateData#state.pause,
				 StateData#state.max_inactivity),
    lists:foreach(fun ({xmlstreamstart, Name, Attrs}) ->
                        ?DEBUG("streamstart", []),
                          send_element(StateData,
                                       {xmlstreamstart, Name, Attrs});
                      ({xmlstreamend, End}) ->
                          ?DEBUG("xmlstreamend", []),
                          send_element(StateData,
                                       {xmlstreamend, End});
                      ({_Name, Element}) ->
                          send_element(StateData, Element)
                  end, Output),
    cancel_timer(StateData#state.wait_timer),
    Reply = ok,
    {reply, Reply, StateName,
     StateData#state{output = [],
		     websocket_receiver = undefined,
		     wait_timer = undefined,
		     timer = Timer}};
%% Handle writing to c2s
handle_sync_event(#wsr{out=Payload, socket=WSocket, sockmod=WSockmod},
                  From, StateName, StateData) ->
    ?DEBUG("in handle sync event", []),
    ?DEBUG("Payload ~p", [Payload]),
    Reply = ok,
    case StateData#state.waiting_input of
        false ->
            ?DEBUG("No c2spid.",[]),
            {reply, Reply, StateName, StateData};
        C2SPid ->
            ?DEBUG("really sending now: ~p", [Payload]),
            lists:foreach(
              fun({xmlstreamend, End}) ->
                        ?DEBUG("streamend", []),
                      gen_fsm:send_event(
                        C2SPid, {xmlstreamend, End});
                 ({xmlelement, "stream:stream", Attrs, []}) ->
                        ?DEBUG("stream start xmlelement", []),
                      send_stream_start(C2SPid, Attrs);
                 ({xmlstreamstart, "stream:stream", Attrs}) ->
                     ?DEBUG("stream start stream:stream", []),
                      send_stream_start(C2SPid, Attrs);
                 (El) ->
                      gen_fsm:send_event(
                        C2SPid, El)
              end, Payload),
            {reply, Reply, StateName,
             StateData#state{websocket_s=WSocket,
                             websocket_sockmod=WSockmod,
                             websocket_receiver=From}}
    end;
handle_sync_event({stop,close}, _From, _StateName, StateData) ->
    ?DEBUG("stop sync event, close", []),
    Reply = ok,
    {stop, normal, Reply, StateData};
handle_sync_event({stop,stream_closed}, _From, _StateName, StateData) ->
    ?DEBUG("stop sync event, stream_closed", []),
    Reply = ok,
    {stop, normal, Reply, StateData};
handle_sync_event({stop, Reason}, _From, _StateName, StateData) ->
    ?DEBUG("Closing websocket session ~p - Reason: ~p",
           [StateData#state.id, Reason]),
    Reply = ok,
    {stop, normal, Reply, StateData};

handle_sync_event(peername, _From, StateName, StateData) ->
    Reply = {ok, StateData#state.ip},
    {reply, Reply, StateName, StateData};

handle_sync_event(_Event, _From, StateName, StateData) ->
    Reply = ok,
    {reply, Reply, StateName, StateData}.

code_change(_OldVsn, StateName, StateData, _Extra) ->
    {ok, StateName, StateData}.

%%----------------------------------------------------------------------
%% Func: handle_info/3
%% Returns: {next_state, NextStateName, NextStateData}          |
%%          {next_state, NextStateName, NextStateData, Timeout} |
%%          {stop, Reason, NewStateData}
%%----------------------------------------------------------------------
%% We reached the max_inactivity timeout:
handle_info({timeout, Timer, _}, _StateName,
	    #state{id=SID, timer = Timer} = StateData) ->
    ?INFO_MSG("Session timeout. Closing the websocket session: ~p", [SID]),
    {stop, normal, StateData};

handle_info({timeout, WaitTimer, _}, StateName,
	    #state{wait_timer = WaitTimer} = StateData) ->
    if
	StateData#state.websocket_receiver /= undefined ->
	    cancel_timer(StateData#state.timer),
	    Timer = set_inactivity_timer(StateData#state.pause,
					 StateData#state.max_inactivity),
	    gen_fsm:reply(StateData#state.websocket_receiver, {ok, empty}),
	    {next_state, StateName,
	     StateData#state{websocket_receiver = undefined,
			     wait_timer = undefined,
			     timer = Timer}};
	true ->
	    {next_state, StateName, StateData}
    end;

handle_info({timeout, ShaperTimer, _}, StateName,
	    #state{shaper_timer = ShaperTimer} = StateData) ->
    {next_state, StateName, StateData#state{shaper_timer = undefined}};

handle_info(_, StateName, StateData) ->
    {next_state, StateName, StateData}.

%%----------------------------------------------------------------------
%% Func: terminate/3
%% Purpose: Shutdown the fsm
%% Returns: any
%%----------------------------------------------------------------------
terminate(_Reason, _StateName, StateData) ->
    ?DEBUG("terminate: Deleting session ~s", [StateData#state.id]),
    send_receiver_reply(StateData#state.websocket_receiver, {ok, terminate}),
    case StateData#state.waiting_input of
	false ->
	    ok;
	C2SPid ->
	    gen_fsm:send_event(C2SPid, closed)
    end,
    ok.
%%%
%% Internal functions
%%%
stream_start(ParsedPayload) ->
    ?DEBUG("Stream start PasedPayload is ~p~n",[ParsedPayload]),
    case ParsedPayload of
        #xmlel{name=Name,
               attrs = Attrs,
               children= Childs} ->
            % {"to",Host} = lists:keyfind("to", 1, Attrs),
            Host = xml:get_attr_s(<<"to">>, Attrs),
            ?DEBUG("Host is ~p~n",[Host]),
            Sid = p1_sha:sha(term_to_binary({now(), make_ref()})),
            %%Sid = sha:sha(term_to_binary({now(), make_ref()})),
            Key = "",
            {Host, Sid, Key};
        _ ->
            ?DEBUG("|||||||||||||||||||||||||||||||||||||||||||||||~n",[]),
            false
    end.
%% validate request sent. ensure that its parsable XMPP
validate_request(Data, PayloadSize, MaxStanzaSize) ->
    ?DEBUG("--- incoming data --- ~n~s~n --- END --- ", [Data]),
    case xml_stream:parse_element(Data) of
        {error, Reason} ->
            ?DEBUG("error parsing element: ~p", [Reason]),
            %% detect stream start and stream end
            case stream_start_end(Data) of
                {xmlstreamstart, Name, Attrs} ->
                    ?DEBUG("xmlstreamstart", []),
                    {ok, {xmlstreamstart, Name, Attrs}};
                {xmlstreamend, End} ->
                    ?DEBUG("xmlstreamend", []),
                    {ok, {xmlstreamend, End}};
                _ ->
                    ?ERROR_MSG("Bad xml data: ~p~n", [Reason]),
                    {error, bad_request}
            end;
        ParsedData ->
            ?DEBUG("parsed: ~p", [ParsedData]),
            if PayloadSize =< MaxStanzaSize ->
                    {ok,  ParsedData};
               true ->
                    {size_limit, {}}
            end
    end.
send_receiver_reply(undefined, _Reply) ->
    ok;
send_receiver_reply(Receiver, Reply) ->
    gen_fsm:reply(Receiver, Reply).

%% send data to socket
send_text(StateData, Text) ->
    ?DEBUG("Send XML on stream = ~p", [Text]),
    ?DEBUG("send format: ~p", [send_format(Text)]),
    ?DEBUG("statedata: ~p", [StateData]),
    ?DEBUG("WS_SOCKET: ~p", [StateData#state.websocket_s]),
    ?DEBUG("Send data: ~p", [(StateData#state.websocket_sockmod):send(StateData#state.websocket_s, send_format(Text))]).
% ----------------------------------------------------------------------------------------------------------
% Function: -> binary() | iolist()
% Description: Callback to format data before it is sent into the socket.
% ----------------------------------------------------------------------------------------------------------
-spec send_format(Data::iolist(), State::term()) -> binary().
send_format(Data) ->
	send_format(Data, ?OP_TEXT).
send_format(Data, OpCode) ->
	BData = erlang:iolist_to_binary(Data),
	Len = erlang:size(BData),
	if
		Len < 126 ->
			<<1:1, 0:3, OpCode:4, 0:1, Len:7, BData/binary>>;
		Len < 65536 ->
			<<1:1, 0:3, OpCode:4, 0:1, 126:7, Len:16, BData/binary>>;
		true ->
			<<1:1, 0:3, OpCode:4, 0:1, 127:7, 0:1, Len:63, BData/binary>>
	end.

send_element(StateData, {xmlstreamstart, Name, Attrs}) ->
    XmlString = streamstart_tobinary({xmlstreamstart, Name, Attrs}),
    send_text(StateData, XmlString);
send_element(StateData, {xmlstreamend, "stream:stream"}) ->
    send_text(StateData, <<"</stream:stream>">>);
send_element(StateData, {xmlstreamend, <<"stream:stream">>}) ->
    send_text(StateData, <<"</stream:stream>">>);
send_element(StateData, El) ->
    send_text(StateData, xml:element_to_binary(El)).

send_stream_start(C2SPid, Attrs) ->
    % StreamTo = case lists:keyfind("to", 1, Attrs) of
    %                {"to", Ato} ->
    %                    case lists:keyfind("version",
    %                                       1, Attrs) of
    %                        {"version", AVersion} ->
    %                            {Ato, AVersion};
    %                        _ ->
    %                            {Ato, ""}
    %                    end
    %            end,
    ToP = xml:get_attr_s(<<"to">>, Attrs),
    VersionP = xml:get_attr_s(<<"version">>, Attrs),
    StreamTo = {ToP, VersionP},
    ?DEBUG("Streaming to ~p", [StreamTo]),
    case StreamTo of
        {To, false} ->
            gen_fsm:send_event(
              C2SPid,
              {xmlstreamstart, "stream:stream",
               [{"to", To},
                {"xmlns", ?NS_CLIENT},
                {"xmlns:stream", ?NS_STREAM}]});
        {To, Version} ->
            gen_fsm:send_event(
              C2SPid,
              {xmlstreamstart, "stream:stream",
               [{"to", To},
                {"xmlns", ?NS_CLIENT},
                {"version", Version},
                {"xmlns:stream", ?NS_STREAM}]})
    end.
send_data(FsmRef, Req) ->
    ?DEBUG("SENDING DATA:", []),
    ?DEBUG("session pid:~p~n", [FsmRef]),
    ?DEBUG("Req is :~p~n", [Req]),
    case FsmRef of
        false ->
            ?DEBUG("No session started.",[]);
        _ ->
            ?DEBUG("Writing data!.",[]),
            %% write data to c2s
            gen_fsm:sync_send_all_state_event(FsmRef, Req)
    end.
%% Cancel timer and empty message queue.
cancel_timer(undefined) ->
    ok;
cancel_timer(Timer) ->
    erlang:cancel_timer(Timer),
    receive
	{timeout, Timer, _} ->
	    ok
    after 0 ->
	    ok
    end.

%% If client asked for a pause (pause > 0), we apply the pause value
%% as inactivity timer:
set_inactivity_timer(Pause, _MaxInactivity) when Pause > 0 ->
    erlang:start_timer(Pause*1000, self(), []);
%% Otherwise, we apply the max_inactivity value as inactivity timer:
set_inactivity_timer(_Pause, MaxInactivity) ->
    erlang:start_timer(MaxInactivity, self(), []).

stream_start_end(Data) ->
    %% find <stream:stream>
    case re:run(Data, "\<stream\:stream.+\>", []) of
        {match, _X} ->
            %% find to and version
            To = case re:run(Data,
                             "to=[\"']?((?:.(?![\"\']?\\s+(?:\\S+)=|[>\"\']))+.)[\"\']?", [{capture,[1]}]) of
                     {match, [{Start, Finish}]} ->
                         lists:sublist(Data, Start+1, Finish);
                     _ ->
                         undefined
                 end,
            Version = case re:run(Data,
                            "version=[\"']?((?:.(?![\"\']?\\s+(?:\\S+)=|[>\"\']))+.)[\"\']?", [{capture,[1]}]) of
                          {match, [{St, Fin}]} ->
                              lists:sublist(Data, St+1, Fin);
                          T ->
                              T
                      end,
            {xmlstreamstart, "stream:stream", [{"to", To},
                                               {"version", Version},
                                               {"xmlns", ?NS_CLIENT},
                                               {"xmlns:stream", ?NS_STREAM}]};
        nomatch ->
            %% find </stream:stream>
            case re:run(Data, "^</stream:stream>", [global]) of
                {match, _Loc} ->
                    {xmlstreamend, "stream:stream"};
                nomatch ->
                    false
            end
    end.

streamstart_tobinary({xmlstreamstart, Name, Attrs}) ->
    XmlStrListStart = io_lib:format("<~s",[Name]),
    RestStr = attrs_tostring("", Attrs),
    list_to_binary([XmlStrListStart,RestStr,">"]).
attrs_tostring(String,[]) ->
    String;
attrs_tostring(Str,[X|Rest]) ->
    {Name, Value} = X,
    AttrStr = io_lib:format(" ~s='~s'",[Name, Value]),
    attrs_tostring([Str,AttrStr], Rest).

%% Tests
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
stream_start_end_test() ->
    false = stream_start_end("stream no xml"),
    {xmlstreamstart, _X, _Y} = stream_start_end("<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.0'>"),
    {xmlstreamend, _Z} = stream_start_end("</stream:stream>").
streamstart_tobinary_test() ->
    TestStr =     <<"<stream:stream to='localhost' xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' version='1.0'>">>,
    io:format("~p~n",[streamstart_tobinary({xmlstreamstart, "stream:stream", [{"to","localhost"}, {"xmlns:stream","http://etherx.jabber.org/streams"}, {"xmlns","jabber:client"}, {"version","1.0"}]})]),
    io:format("~p~n",[TestStr]),
    TestStr = streamstart_tobinary({xmlstreamstart, "stream:stream", [{"to","localhost"}, {"xmlns:stream","http://etherx.jabber.org/streams"}, {"xmlns","jabber:client"}, {"version","1.0"}]}).
-endif.
