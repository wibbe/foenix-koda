
const SYS_EXIT 				= 0x00
const SYS_INT_REGISTER  	= 0x02
const SYS_INT_ENABLE    	= 0x03
const SYS_INT_DISABLE		= 0x04
const SYS_CHAN_READ 		= 0x10
const SYS_CHAN_READ_B		= 0x11
const SYS_CHAN_WRITE		= 0x13
const SYS_CHAN_WRITE_B		= 0x14
const SYS_KEYBOARD_SCANCODE	= 0x53

const INT_VKY_START_OF_FRAME	= 0x00
const INT_VKY_START_OF_LINE		= 0x01
const INT_VKY_SPRITE_COLLISION	= 0x02
const INT_VKY_BITMAP_COLLISION	= 0x03


func sys_exit() {
	syscall0(SYS_EXIT)
}

func sys_int_enable(number) {
    syscall1(SYS_INT_ENABLE, number)
}

func sys_int_disable(number) {
    syscall1(SYS_INT_DISABLE, number)
}

func sys_int_register(number, callback) {
    syscall2(SYS_INT_REGISTER, number, callback)
}

func sys_chan_read(channel, data, len) {
	syscall3(SYS_CHAN_READ, channel, data, len)
}

func sys_chan_read_b(channel) {
	return syscall1(SYS_CHAN_READ_B, channel)
}

func sys_chan_write(channel, data, len) {
	syscall3(SYS_CHAN_WRITE, channel, data, len)
}

func sys_chan_write_b(channel, ch) {
	syscall2(SYS_CHAN_WRITE_B, channel, ch)
}

func sys_keyboard_scancode() {
    return syscall0(SYS_KEYBOARD_SCANCODE)
}

func str_length(str) {
	return memscan(str, 0, 0x8FFF)
}

func to_str(num) {
	var i, k

	k = num < 0 ? -num : num
	i = 0

	if (num == 0) {
		return "0"
	}

	while (k > 0) {
		i = i + 1
		k = k / 10
	}
	
	i = i + 1

	if (num < 0) {
		i = i + 1
	}

	__buffer::i = 0
	k = num < 0 ? -num : num

	while (k > 0) {
		i = i - 1
		__buffer::i = '0' + k % 10
		k = k / 10
	}

	if (num < 0) {
		i = i - 1
		__buffer::i = '-'
	}

	return @__buffer::i
}

func print_str(str) {
	var len
	len = memscan(str, 0, 0x8FFF)
	syscall3(SYS_CHAN_WRITE, 0, str, len)
}

func print_char(ch) {
	syscall2(SYS_CHAN_WRITE_B, 0, ch)
}

func print_num(num) {
	var str
	str = to_str(num)
	print_str(str)
}

func print(format, args) {
	var i, j, ch
	i = 0
	j = 0

	ch = format::i
	while (ch != 0) {
		i = i + 1

		if (ch == '%') {
			ch = format::i
			i = i + 1

			if (ch == 'd') {
				print_str(to_str(args[j]))
				j = j + 1
			}
			if (ch == 's') {
				print_str(args[j])
				j = j + 1
			}
			if (ch == 'c') {
				syscall2(SYS_CHAN_WRITE_B, 0, args[j])
				j = j + 1
			}
			if (ch == '%') {
				syscall2(SYS_CHAN_WRITE_B, 0, '%')
			}
		} else {
			syscall2(SYS_CHAN_WRITE_B, 0, ch)
		}

		ch = format::i
	}
}

func heap_available() {
	return HEAP_END - __heap_ptr
}

func heap_reset() {
	__heap_ptr = HEAP_START
}

func heap_record() {
	return __heap_ptr
}

func heap_rewind(pos) {
	if (pos >= HEAP_START && pos <= HEAP_END) {
		__heap_ptr = pos
	}
}

func heap_alloc(size) {
	var ptr

	// divide size by 4 add 1 and multiply by 4 to get the word aligned size
	size = ((size >> 2) + 1) << 2
	if (heap_available() < size) {
		return 0
	}

	ptr = __heap_ptr
	__heap_ptr = __heap_ptr + size
	return ptr
}