import angr
import claripy

p = angr.Project("./prob")

flag_chars = [claripy.BVS('flag_%d' %i, 8) for i in range(8)]
flag = claripy.Concat(*flag_chars)
#flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

st = p.factory.full_init_state(
        add_options=angr.options.unicorn,
        stdin=flag
        )   

for k in flag_chars:
    st.solver.add(k < 0x67)
    st.solver.add(k > 0x2f)

sm = p.factory.simulation_manager(st)
sm.run()

for i in sm.deadended:
    if b'Success.' in i.posix.dumps(1):
        print(f"ans: {i.posix.dumps(0)}")