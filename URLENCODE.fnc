CREATE function urlencode( p_str in varchar2 ) return varchar2
as
    l_tmp   varchar2(6000);
    l_bad   varchar2(100) default ' >%}\~];?@&<#{|^[`/:=$+''"';
    l_char  char(1);
begin
    for i in 1 .. nvl(length(p_str),0) loop
        l_char :=  substr(p_str,i,1);
        if ( instr( l_bad, l_char ) > 0 )
        then
            l_tmp := l_tmp || '%' ||
                            to_char( ascii(l_char), 'fmXX' );
        else
            l_tmp := l_tmp || l_char;
        end if;
    end loop;

    return l_tmp;
end;
/
