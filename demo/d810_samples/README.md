# Samples Description

Samples used to showcase D-810:
* *anel.zip*: ANEL malware sample (password: infected)
    * Original sample can be found [here](https://github.com/malrev/ABD)
    * Detailled analysis can be found in [VMware Carbon Black blog post](https://www.carbonblack.com/blog/defeating-compiler-level-obfuscations-used-in-apt10-malware/)
    * In D-810, use the *example_anel.json* configuration
    * Obfuscation: O-LLVM 
        * [Control Flow flattening](https://github.com/obfuscator-llvm/obfuscator/wiki/Control-Flow-Flattening)
        * [Bogus Control Flow](https://github.com/obfuscator-llvm/obfuscator/wiki/Bogus-Control-Flow)
        * [Instruction Substitutions](https://github.com/obfuscator-llvm/obfuscator/wiki/Instructions-Substitution)

* *blog_instruction_obfuscation_sub1.bin*: Sample used in [eShard blog post](https://eshard.com/posts/d810_blog_post_1/)
    * In D-810, use the *default_instruction_only.json* configuration
    * Obfuscation: O-LLVM and manual
        * [Instruction Substitutions](https://github.com/obfuscator-llvm/obfuscator/wiki/Instructions-Substitution) with 1 pass
        * Constant obfuscation
        * Opaque predicate

* *blog_instruction_obfuscation_sub2.bin*: Sample used in [eShard blog post](https://eshard.com/posts/d810_blog_post_1/)
    * Same as *blog_instruction_obfuscation_sub1.bin* but with more O-LLVM passes. 
    * In D-810, use the *default_instruction_only.json* configuration
    * Obfuscation: O-LLVM and manual
        * [Instruction Substitutions](https://github.com/obfuscator-llvm/obfuscator/wiki/Instructions-Substitution) with 2 passes
        * Constant obfuscation
        * Opaque predicate

* *qsynth_dataset_custom_ea.bin*: Sample created from [QSynth dataset](https://github.com/werew/qsynth-artifacts/)
    * Randomly generated function obfuscated with Tigress
    * In D-810, use the *default_instruction_only.json* configuration
    * Obfuscation: Tigress
        * [EncodeArithmetic](https://tigress.wtf/encodeArithmetic.html) 

* *libobfuscated.so*: Sample used to showcase control flow unflatening using multiple techniques
    * In D-810, use the *example_libobfuscated.json* configuration
    * Obfuscation: Tigress
        * [EncodeArithmetic](https://tigress.wtf/encodeArithmetic.html) 
        * [TigressFlatten](https://tigress.wtf/flatten.html) with *switch* and *indirect* dispatcher
    * Obfuscation: O-LLVM 
        * [Control Flow flattening](https://github.com/obfuscator-llvm/obfuscator/wiki/Control-Flow-Flattening)
        * [Bogus Control Flow](https://github.com/obfuscator-llvm/obfuscator/wiki/Bogus-Control-Flow)
        * [Instruction Substitutions](https://github.com/obfuscator-llvm/obfuscator/wiki/Instructions-Substitution)

