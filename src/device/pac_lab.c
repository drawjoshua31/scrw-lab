/*
 * pac_lab.c - see what PAC actually does, on your own device, in userland.
 *
 * This is the cheapest way to stop guessing about PAC. It signs one function
 * pointer with different keys and diversifiers and prints the results, then
 * authenticates one of them and calls it. Nothing here touches the kernel and
 * nothing here bypasses anything: the point is to make the mechanism concrete
 * before you reason about the kernel's use of it.
 *
 * What you should take away:
 *
 *   - The PAC is stored in the upper bits of the pointer itself. Strip it and
 *     you get the canonical address back.
 *   - The same address signed with a different key or discriminator produces a
 *     different pointer. There is no single "the PAC": it is a family of MACs
 *     over (pointer, context), keyed by secrets you cannot read.
 *   - Therefore "bypassing PAC" by computing a valid PAC is not a thing. Real
 *     bypasses either (a) make the kernel sign or authenticate on your behalf
 *     through a legitimate path (exception return, thread-state restore, a
 *     signed gadget), or (b) avoid the signed pointer entirely.
 *   - A corrupted signed pointer traps exactly where the kernel authenticates
 *     it. That is your panic: PAC working as designed, not PAC being broken.
 *
 * Build: scripts/build_device.sh pac_lab
 *
 *   pac_lab                 # sign/auth round trip, no crash
 *   pac_lab --crash-demo    # corrupt the PAC and call it (kills THIS process)
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(__arm64e__) && __has_include(<ptrauth.h>)
#include <ptrauth.h>
#define PAC_LAB_HAVE_PAC 1
#else
#define PAC_LAB_HAVE_PAC 0
#endif

static int target_fn(int x)
{
    return x * 3 + 1;
}

typedef int (*fn_t)(int);

#if PAC_LAB_HAVE_PAC

static void show(const char *label, const void *p)
{
    printf("  %-28s %016llx\n", label, (unsigned long long)(uintptr_t)p);
}

#endif

int main(int argc, char **argv)
{
    int crash_demo = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--crash-demo") == 0) {
            crash_demo = 1;
        }
    }

#if !PAC_LAB_HAVE_PAC
    (void)crash_demo;
    printf("not building for arm64e, or <ptrauth.h> is unavailable.\n");
    printf("compile with -arch arm64e on an A12+ device.\n");
    return 0;
#else
    {
        void *stripped =
            ptrauth_strip((void *)target_fn, ptrauth_key_function_pointer);
        void *p_ia0 = ptrauth_sign_unauthenticated(
            stripped, ptrauth_key_function_pointer, 0);
        void *p_ia1 = ptrauth_sign_unauthenticated(
            stripped, ptrauth_key_function_pointer, 1);
        void *p_da0 =
            ptrauth_sign_unauthenticated(stripped, ptrauth_key_data, 0);
        fn_t callable;

        printf("PAC lab\n\n");
        show("raw (stripped) address", stripped);
        show("signed, IA key, disc 0", p_ia0);
        show("signed, IA key, disc 1", p_ia1);
        show("signed, DA key, disc 0", p_da0);

        printf("\nsame address?   %s\n", stripped == (void *)(uintptr_t)target_fn ? "yes" : "no");
        printf("IA0 == IA1?       %s\n", p_ia0 == p_ia1 ? "yes" : "no");
        printf("IA0 == DA0?            %s\n", p_ia0 == p_da0 ? "yes" : "no");
        printf("\nDifferent keys/diversifiers give different pointers for the same\n" "  address. The kernel's keys are not reachable from here, so there is\n" "  nothing to compute. Plan around the pointer, not the MAC.\n");
        printf("\nstring discriminator for \"com.apple.example\": 0x%llx\n", (unsigned long long)ptrauth_string_discriminator("com.apple.example"));

        callable = (fn_t)ptrauth_auth_function(p_ia0, ptrauth_key_function_pointer, 0);
        printf("call through authenticated pointer: %d (expected 22)\n", callable(7));

        if (crash_demo) {
            uintptr_t bits = (uintptr_t)p_ia0;
            void *corrupt = (void *)(bits ^ (1ULL << 40));
            fn_t bad;

            printf("\n  --crash-demo: flipping bit 40 of the signed pointer and calling\n""  it. This terminates THIS PROCESS with a PAC trap. It does not\n" "  panic the kernel, and it will not teach you anything the kernel\n" "  panic has not already told you. Go ahead.\n");
            fflush(stdout);
            bad = (fn_t)ptrauth_auth_function(corrupt, ptrauth_key_function_pointer, 0);
            printf("  unreachable: %d\n", bad(7));
        }
    }
    return 0;
#endif
}
