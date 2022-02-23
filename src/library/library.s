
function: macro
	dc.b 	$02
    dc.l    \2          ; start offset
    dc.b    \3          ; arity
    dc.b    \1,0        ; name (zero terminated)
endm

const: macro
	dc.b 	$01
    dc.l    \2          ; value
    dc.b    \1,0        ; name
endm