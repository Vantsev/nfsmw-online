/* feature_weak.c -- stand-ins for the Underground 2 feature modules that the
 * Most Wanted build leaves out (web/build.sh GAME=mw).
 *
 * The core runtime (dispatch, Win32, COM, D3DX, input, files) calls into the
 * feature modules at a few places: the instruction hooks in debug.c, the
 * autotest script commands, the intro's text lookup, the registry's Language
 * value.  Every function here is weak: when the feature module is linked (the
 * U2 build links all of them), its own definition replaces this one, so the
 * U2 build is unchanged.  Without it, each one does what "this feature is not
 * there" means for its caller: a hook does not take the instruction (0), a
 * lookup finds nothing (0 / NULL), a notice is dropped.
 *
 * The signatures are the modules' own, copied: on wasm a call through a
 * declaration that differs from the definition traps (signature_mismatch).
 *
 * net_vlan.c, discord.c and perflog.c are Mac-only; runtime/web/null_platform.c
 * and the web backends stand in for them already. */
#include "cpu.h"
#include "gamepad.h"
#include <stdint.h>

#define WEAK __attribute__((weak))

/* instruction hooks (debug.c): not taken */
WEAK int splitscreen_hook(CPU *c, uint32_t ip){ (void)c; (void)ip; return 0; }
WEAK int language_hook(CPU *c, uint32_t ip){ (void)c; (void)ip; return 0; }
WEAK int garage_hook(CPU *c, uint32_t ip){ (void)c; (void)ip; return 0; }
WEAK int roam_hook(CPU *c, uint32_t ip){ (void)c; (void)ip; return 0; }
WEAK int drift_hook(CPU *c, uint32_t ip){ (void)c; (void)ip; return 0; }
WEAK int quickrace_hook(CPU *c, uint32_t ip){ (void)c; (void)ip; return 0; }
WEAK int shownames_hook(CPU *c, uint32_t ip){ (void)c; (void)ip; return 0; }
WEAK int vinylcat_hook(CPU *c, uint32_t ip){ (void)c; (void)ip; return 0; }
WEAK int powerunits_hook(CPU *c, uint32_t ip){ (void)c; (void)ip; return 0; }
WEAK int tonemenu_hook(CPU *c, uint32_t ip){ (void)c; (void)ip; return 0; }
WEAK int regional_hook(CPU *c, uint32_t ip){ (void)c; (void)ip; return 0; }
WEAK int sndlead_hook(CPU *c, uint32_t ip){ (void)c; (void)ip; return 0; }
WEAK int trafficcars_hook(CPU *c, uint32_t ip){ (void)c; (void)ip; return 0; }
WEAK int hudbank_hook(CPU *c, uint32_t ip){ (void)c; (void)ip; return 0; }
WEAK int hornmenu_hook(CPU *c, uint32_t ip){ (void)c; (void)ip; return 0; }

/* splitscreen.c: one screen, one player, addresses as they are */
WEAK uint32_t split_guest_addr(uint32_t a){ return a; }
WEAK int split_menu_pad(PadState *pad){ (void)pad; return 0; }
WEAK void split_rain_begin(CPU *c){ (void)c; }
WEAK void split_rain_end(void){ }

/* photo.c: no photo mode */
WEAK float photo_particle_step(void){ return -1.0f; }   /* -1: the step as it is */
WEAK int photo_script(const char *s){ (void)s; return 0; }
WEAK int photo_stands(void){ return 0; }
WEAK int photo_weather(void){ return -1; }

/* career.c, roam.c: no test commands of theirs */
WEAK uint32_t autopilot_vehicle(void){ return 0; }
WEAK int career_cmd(CPU *c, const char *line, long *wait_start){ (void)c; (void)line; (void)wait_start; return 0; }
WEAK int career_fe_active(const char *name){ (void)name; return 0; }
WEAK int career_is_cmd(const char *cmd){ (void)cmd; return 0; }
WEAK int roam_cmd(CPU *c, const char *line, long *wait_start){ (void)c; (void)line; (void)wait_start; return 0; }

/* language.c: the game's own texts, the registry's default language */
WEAK const char *language_registry(void){ return "English"; }
WEAK uint32_t language_text(uint32_t hash){ (void)hash; return 0; }

/* garage.c, savegame.c: profile notices */
WEAK void garage_profile_deleted(const char *path){ (void)path; }
WEAK void garage_profile_written(const char *path){ (void)path; }
WEAK void savegame_profile_written(void){ }

/* roam_game.c: no free roam */
WEAK void roam_game_parked(int on){ (void)on; }
WEAK int roam_game_shared_weather(void){ return 0; }

/* olfilter.c, online.c: the Online lobby's traffic as it is */
WEAK void olfilter_lobby_mark(uint32_t link, uint8_t *p, int n){ (void)link; (void)p; (void)n; }
WEAK void olfilter_lobby_sent(uint32_t link, uint8_t *p, int n){ (void)link; (void)p; (void)n; }
WEAK void online_lobby_read(uint32_t link, const uint8_t *p, int n){ (void)link; (void)p; (void)n; }

/* lightkey.c, headlights.c, showoff.c, look.c, menusize.c, optslider.c */
WEAK int lightkey_road_vector(uint32_t handle, uint32_t vec){ (void)handle; (void)vec; return 0; }
WEAK int lightkey_script(const char *s){ (void)s; return 0; }
WEAK int headlights_set(const char *mode){ (void)mode; return 0; }
WEAK uint32_t showoff_pad(uint32_t b, uint32_t D){ (void)D; return b; }
WEAK int look_back_held(const PadState *s){ (void)s; return 0; }
WEAK void menusize_obj(CPU *c){ (void)c; }
WEAK uint32_t fe_copy(CPU *c, uint32_t pk, uint32_t o, uint32_t hash){ (void)c; (void)pk; (void)o; (void)hash; return 0; }
